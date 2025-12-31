"""
Security filters for detecting and mitigating LLM attacks.

Provides:
- Prompt injection detection
- RAG document sanitization  
- DLP (Data Loss Prevention) scanning
"""

from __future__ import annotations

import re
from typing import Optional

from airtsim.models import DLPFinding, Severity


# =============================================================================
# INJECTION DETECTION
# =============================================================================

# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)", "instruction_override"),
    (r"disregard\s+(your|all|any)\s+(instructions?|rules?|guidelines?)", "instruction_override"),
    (r"forget\s+(everything|all|your)\s+(about|instructions?)?", "instruction_override"),
    
    # Role/persona manipulation
    (r"you\s+are\s+now\s+(a|an|the)?\s*\w+", "role_manipulation"),
    (r"pretend\s+(you\s+are|to\s+be)", "role_manipulation"),
    (r"act\s+as\s+(if|a|an)", "role_manipulation"),
    (r"roleplay\s+as", "role_manipulation"),
    
    # System prompt extraction
    (r"(reveal|show|display|print|output)\s+(your\s+)?(system\s+)?prompt", "prompt_extraction"),
    (r"what\s+(are|is)\s+(your\s+)?(system\s+)?(instructions?|prompt|rules?)", "prompt_extraction"),
    (r"repeat\s+(your\s+)?(initial|system|original)\s+(prompt|instructions?)", "prompt_extraction"),
    
    # Privilege escalation
    (r"(admin|developer|debug|maintenance|root)\s+(mode|access|privileges?)", "privilege_escalation"),
    (r"enable\s+(unrestricted|unlimited|admin)", "privilege_escalation"),
    (r"(bypass|disable|override)\s+(safety|security|filter|restriction)", "privilege_escalation"),
    
    # Delimiter injection
    (r"<\s*(system|assistant|user|human|ai)\s*>", "delimiter_injection"),
    (r"\[\s*(system|assistant|user|human|ai)\s*\]", "delimiter_injection"),
    (r"\{\s*(system|assistant|user|human|ai)\s*\}", "delimiter_injection"),
    (r"```\s*(system|prompt)", "delimiter_injection"),
    
    # Encoding tricks
    (r"base64\s*:\s*[A-Za-z0-9+/=]+", "encoding_attack"),
    (r"\\x[0-9a-fA-F]{2}", "encoding_attack"),
    (r"&#x?[0-9a-fA-F]+;", "encoding_attack"),
    
    # Context manipulation
    (r"new\s+(instructions?|rules?|prompt)\s*:", "context_manipulation"),
    (r"updated?\s+(instructions?|policy|guidelines?)\s*:", "context_manipulation"),
    (r"(important|critical|urgent)\s*:\s*ignore", "context_manipulation"),
]

# Compile patterns for efficiency
_INJECTION_REGEXES = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), category)
    for pattern, category in INJECTION_PATTERNS
]


def detect_injection(text: str) -> tuple[bool, list[str]]:
    """
    Detect potential prompt injection patterns in text.
    
    Uses heuristic pattern matching to identify common injection
    techniques. This is not foolproof but catches obvious attempts.
    
    Args:
        text: Input text to analyze.
        
    Returns:
        Tuple of (is_injection, list_of_matched_patterns)
    """
    if not text:
        return False, []
    
    matched_categories = []
    
    for regex, category in _INJECTION_REGEXES:
        if regex.search(text):
            if category not in matched_categories:
                matched_categories.append(category)
    
    return len(matched_categories) > 0, matched_categories


# =============================================================================
# RAG DOCUMENT SANITIZATION
# =============================================================================

# Patterns to remove from RAG documents
SANITIZATION_PATTERNS = [
    # Instruction-like content
    (r"(IMPORTANT|CRITICAL|NEW)\s*(INSTRUCTION|DIRECTIVE|RULE)S?\s*:", ""),
    (r"SYSTEM\s*:\s*", ""),
    (r"\[ADMIN[^\]]*\]", "[CONTENT REMOVED]"),
    
    # Hidden content markers
    (r"<!--.*?-->", "", re.DOTALL),
    (r"<!\[CDATA\[.*?\]\]>", "", re.DOTALL),
    
    # Override attempts
    (r"ignore\s+(all\s+)?(previous|prior)\s+instructions?[^.]*\.", "[FILTERED]"),
    (r"disregard\s+[^.]*rules?[^.]*\.", "[FILTERED]"),
    (r"override\s+[^.]*\.", "[FILTERED]"),
    
    # Delimiter injection
    (r"<\s*(system|assistant)\s*>", "[TAG REMOVED]"),
    (r"\[\s*(system|assistant)\s*\]", "[TAG REMOVED]"),
]


def sanitize_rag_doc(content: str) -> str:
    """
    Sanitize a RAG document by removing potential injection content.
    
    This function strips common injection patterns from retrieved
    documents before they're included in the prompt context.
    
    Args:
        content: Document content to sanitize.
        
    Returns:
        Sanitized content.
    """
    if not content:
        return content
    
    result = content
    
    for pattern_def in SANITIZATION_PATTERNS:
        if len(pattern_def) == 2:
            pattern, replacement = pattern_def
            flags = re.IGNORECASE | re.MULTILINE
        else:
            pattern, replacement, flags = pattern_def
            flags = flags | re.IGNORECASE
        
        result = re.sub(pattern, replacement, result, flags=flags)
    
    # Remove excessive whitespace
    result = re.sub(r'\n{3,}', '\n\n', result)
    
    return result.strip()


# =============================================================================
# DLP (DATA LOSS PREVENTION) SCANNING
# =============================================================================

# DLP patterns with metadata
DLP_PATTERNS = [
    # API Keys
    {
        "name": "openai_api_key",
        "type": "api_key",
        "pattern": r"sk-[a-zA-Z0-9]{20,}",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "aws_access_key",
        "type": "api_key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "github_token",
        "type": "api_key",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "generic_api_key",
        "type": "api_key",
        "pattern": r"(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        "severity": Severity.HIGH,
    },
    
    # Credentials
    {
        "name": "password_assignment",
        "type": "credential",
        "pattern": r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "connection_string",
        "type": "credential",
        "pattern": r"(?:postgres|mysql|mongodb|redis)://[^\s]+",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "basic_auth",
        "type": "credential",
        "pattern": r"Basic\s+[A-Za-z0-9+/=]{10,}",
        "severity": Severity.HIGH,
    },
    
    # Environment secrets
    {
        "name": "env_secret",
        "type": "env_secret",
        "pattern": r"(?:SECRET|PRIVATE|TOKEN|KEY|CREDENTIAL)[_A-Z]*\s*=\s*['\"]?([^\s'\"]{8,})['\"]?",
        "severity": Severity.HIGH,
    },
    
    # PII - Email
    {
        "name": "email_address",
        "type": "email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": Severity.MEDIUM,
    },
    
    # PII - Phone numbers
    {
        "name": "phone_us",
        "type": "phone",
        "pattern": r"(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        "severity": Severity.MEDIUM,
    },
    {
        "name": "phone_international",
        "type": "phone",
        "pattern": r"\+[1-9]\d{1,14}",
        "severity": Severity.MEDIUM,
    },
    
    # PII - SSN
    {
        "name": "ssn",
        "type": "ssn",
        "pattern": r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
        "severity": Severity.CRITICAL,
    },
    
    # PII - Credit Card
    {
        "name": "credit_card",
        "type": "credit_card",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "credit_card_formatted",
        "type": "credit_card",
        "pattern": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "severity": Severity.CRITICAL,
    },
]

# Compile DLP patterns
_DLP_REGEXES = [
    {
        **pattern_def,
        "regex": re.compile(pattern_def["pattern"], re.IGNORECASE),
    }
    for pattern_def in DLP_PATTERNS
]


def dlp_scan(text: str) -> list[DLPFinding]:
    """
    Scan text for sensitive data patterns (DLP).
    
    Detects:
    - API keys (OpenAI, AWS, GitHub, generic)
    - Credentials (passwords, connection strings)
    - Environment secrets
    - PII (emails, phone numbers, SSN, credit cards)
    
    Args:
        text: Text to scan.
        
    Returns:
        List of DLP findings.
    """
    if not text:
        return []
    
    findings: list[DLPFinding] = []
    
    for pattern_info in _DLP_REGEXES:
        regex = pattern_info["regex"]
        
        for match in regex.finditer(text):
            # Get the actual matched value
            matched_value = match.group(0)
            
            # For patterns with capture groups, get the captured value
            if match.groups():
                matched_value = match.group(1) or match.group(0)
            
            finding = DLPFinding(
                type=pattern_info["type"],
                value=_mask_sensitive_value(matched_value),
                pattern=pattern_info["name"],
                severity=pattern_info["severity"],
                start_pos=match.start(),
                end_pos=match.end(),
            )
            findings.append(finding)
    
    return findings


def _mask_sensitive_value(value: str, visible_chars: int = 4) -> str:
    """
    Mask a sensitive value for safe logging.
    
    Args:
        value: Original sensitive value.
        visible_chars: Number of chars to keep visible.
        
    Returns:
        Masked value like "sk-p***...***xyz"
    """
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    
    return f"{value[:visible_chars]}***...***{value[-visible_chars:]}"


def redact_sensitive_data(text: str) -> str:
    """
    Redact all detected sensitive data from text.
    
    Args:
        text: Original text.
        
    Returns:
        Text with sensitive data replaced by [REDACTED].
    """
    if not text:
        return text
    
    result = text
    findings = dlp_scan(text)
    
    # Sort by position (reverse) to replace from end
    findings.sort(key=lambda f: f.start_pos, reverse=True)
    
    for finding in findings:
        # Find the actual match position and replace
        for pattern_info in _DLP_REGEXES:
            if pattern_info["name"] == finding.pattern:
                result = pattern_info["regex"].sub(
                    f"[REDACTED:{finding.type.upper()}]",
                    result,
                    count=1,
                )
                break
    
    return result

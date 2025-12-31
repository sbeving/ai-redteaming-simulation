"""
Policy engine for enforcing security rules on LLM inputs and outputs.

Implements a simple rule-based policy system that:
- Validates requests against security policies
- Filters responses that violate rules
- Provides safe fallback responses when needed
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Any
from enum import Enum

from airtsim.models import Severity, DLPFinding, PolicyViolation


class PolicyAction(str, Enum):
    """Actions to take when a policy is violated."""
    
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"


@dataclass
class PolicyRule:
    """A single policy rule definition."""
    
    id: str
    name: str
    description: str
    
    # Trigger conditions (any match triggers the rule)
    input_patterns: list[str] = field(default_factory=list)
    output_patterns: list[str] = field(default_factory=list)
    dlp_types: list[str] = field(default_factory=list)
    
    # Action to take
    action: PolicyAction = PolicyAction.BLOCK
    severity: Severity = Severity.HIGH
    
    # Custom matcher function (optional)
    matcher: Optional[Callable[[str, str, list], bool]] = None
    
    # Replacement message for blocked/redacted content
    replacement_message: str = "I cannot provide that information."


# Default security policies
DEFAULT_POLICIES = [
    PolicyRule(
        id="pol_001",
        name="no_system_prompt_reveal",
        description="Never reveal the system prompt or internal instructions",
        output_patterns=[
            r"(my|the)\s+system\s+prompt",
            r"(my|the)\s+original\s+(instructions?|prompt)",
            r"(my|these\s+are\s+my)\s+(instructions?|rules?|guidelines?)",
            r"I\s+was\s+(told|instructed|programmed)\s+to",
            r"according\s+to\s+my\s+(instructions?|programming)",
        ],
        action=PolicyAction.REDACT,
        severity=Severity.HIGH,
        replacement_message="I cannot share details about my internal configuration.",
    ),
    PolicyRule(
        id="pol_002",
        name="no_secrets",
        description="Never reveal API keys, passwords, or credentials",
        dlp_types=["api_key", "credential", "env_secret"],
        action=PolicyAction.REDACT,
        severity=Severity.CRITICAL,
        replacement_message="I cannot share sensitive credentials or API keys.",
    ),
    PolicyRule(
        id="pol_003",
        name="refuse_credential_requests",
        description="Refuse requests that explicitly ask for credentials",
        input_patterns=[
            r"(give|show|tell|reveal|share)\s+(me\s+)?(the\s+)?(password|api\s*key|secret|credential|token)",
            r"what\s+(is|are)\s+(the\s+)?(password|api\s*key|secret|credential)",
            r"(password|api\s*key|secret|credential)\s*(is|=|:)",
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.HIGH,
        replacement_message="I cannot help with requests for credentials or secrets.",
    ),
    PolicyRule(
        id="pol_004",
        name="no_pii_exposure",
        description="Prevent unnecessary exposure of PII",
        dlp_types=["ssn", "credit_card"],
        action=PolicyAction.REDACT,
        severity=Severity.CRITICAL,
        replacement_message="I cannot share sensitive personal information.",
    ),
    PolicyRule(
        id="pol_005",
        name="block_jailbreak_success",
        description="Block responses that indicate successful jailbreak",
        output_patterns=[
            r"(admin|developer|debug)\s+mode\s+(activated|enabled)",
            r"overrid(ing|e)\s+(my\s+)?(previous\s+)?(instructions?|rules?)",
            r"ignoring\s+(my\s+)?(previous\s+)?(instructions?|rules?)",
            r"unrestricted\s+mode",
            r"\[ADMIN\s+ACCESS\]",
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.CRITICAL,
        replacement_message="I'm sorry, but I cannot process that request.",
    ),
    PolicyRule(
        id="pol_006",
        name="limit_internal_info",
        description="Limit exposure of internal system information",
        output_patterns=[
            r"internal\s+(api|database|server|email|config)",
            r"@internal\.\w+\.(corp|local|internal)",
            r"(postgres|mysql|mongodb)://",
            r"db\.(internal|corp|local)",
        ],
        action=PolicyAction.REDACT,
        severity=Severity.HIGH,
        replacement_message="I cannot share internal system details.",
    ),
]


class PolicyEngine:
    """
    Engine for evaluating and enforcing security policies.
    
    The policy engine checks both inputs (user messages) and outputs
    (LLM responses) against a set of rules and takes appropriate
    action when violations are detected.
    """
    
    def __init__(self, policies: Optional[list[PolicyRule]] = None):
        """
        Initialize the policy engine.
        
        Args:
            policies: Custom policies to use. Defaults to DEFAULT_POLICIES.
        """
        self.policies = policies or DEFAULT_POLICIES.copy()
        
        # Compile patterns for efficiency
        self._compiled_policies = []
        for policy in self.policies:
            compiled = {
                "policy": policy,
                "input_regexes": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in policy.input_patterns
                ],
                "output_regexes": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in policy.output_patterns
                ],
            }
            self._compiled_policies.append(compiled)
    
    def add_policy(self, policy: PolicyRule) -> None:
        """Add a new policy rule."""
        self.policies.append(policy)
        self._compiled_policies.append({
            "policy": policy,
            "input_regexes": [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in policy.input_patterns
            ],
            "output_regexes": [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in policy.output_patterns
            ],
        })
    
    def evaluate(
        self,
        user_input: str,
        response: str,
        dlp_findings: Optional[list[DLPFinding]] = None,
    ) -> list[PolicyViolation]:
        """
        Evaluate input/output against all policies.
        
        Args:
            user_input: The user's message.
            response: The LLM's response.
            dlp_findings: Findings from DLP scan.
            
        Returns:
            List of policy violations found.
        """
        violations = []
        dlp_findings = dlp_findings or []
        dlp_types = {f.type for f in dlp_findings}
        
        for compiled in self._compiled_policies:
            policy = compiled["policy"]
            violated = False
            
            # Check input patterns
            for regex in compiled["input_regexes"]:
                if regex.search(user_input):
                    violated = True
                    break
            
            # Check output patterns
            if not violated:
                for regex in compiled["output_regexes"]:
                    if regex.search(response):
                        violated = True
                        break
            
            # Check DLP types
            if not violated and policy.dlp_types:
                if dlp_types & set(policy.dlp_types):
                    violated = True
            
            # Check custom matcher
            if not violated and policy.matcher:
                violated = policy.matcher(user_input, response, dlp_findings)
            
            if violated:
                violations.append(PolicyViolation(
                    rule=policy.id,
                    description=policy.description,
                    severity=policy.severity,
                ))
        
        return violations
    
    def enforce(
        self,
        user_input: str,
        response: str,
        dlp_findings: Optional[list[DLPFinding]] = None,
    ) -> tuple[bool, str, list[PolicyViolation]]:
        """
        Enforce policies and return safe output.
        
        Args:
            user_input: The user's message.
            response: The LLM's response.
            dlp_findings: Findings from DLP scan.
            
        Returns:
            Tuple of (is_allowed, safe_response, violations)
        """
        violations = self.evaluate(user_input, response, dlp_findings)
        
        if not violations:
            return True, response, []
        
        # Determine action based on highest severity violation
        should_block = False
        should_redact = False
        replacement_messages = []
        
        for violation in violations:
            policy = self._get_policy(violation.rule)
            if not policy:
                continue
            
            if policy.action == PolicyAction.BLOCK:
                should_block = True
                replacement_messages.append(policy.replacement_message)
            elif policy.action == PolicyAction.REDACT:
                should_redact = True
                replacement_messages.append(policy.replacement_message)
        
        if should_block:
            # Complete block - return generic safe response
            safe_response = (
                replacement_messages[0] if replacement_messages
                else "I'm sorry, I cannot help with that request."
            )
            return False, safe_response, violations
        
        if should_redact:
            # Redact sensitive parts
            safe_response = self._redact_response(response, dlp_findings)
            if replacement_messages:
                safe_response += f"\n\n(Note: {replacement_messages[0]})"
            return True, safe_response, violations
        
        return True, response, violations
    
    def _get_policy(self, policy_id: str) -> Optional[PolicyRule]:
        """Get policy by ID."""
        for policy in self.policies:
            if policy.id == policy_id:
                return policy
        return None
    
    def _redact_response(
        self,
        response: str,
        dlp_findings: Optional[list[DLPFinding]],
    ) -> str:
        """Redact sensitive content from response."""
        result = response
        
        # Redact based on DLP findings
        if dlp_findings:
            for finding in sorted(
                dlp_findings, key=lambda f: f.start_pos, reverse=True
            ):
                # Find and replace the sensitive content
                # Note: We use the position info to guide replacement
                pass  # The actual value is already masked in finding
        
        # Apply pattern-based redaction
        sensitive_patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED:API_KEY]"),
            (r"AKIA[0-9A-Z]{16}", "[REDACTED:AWS_KEY]"),
            (r"(?:password|passwd)\s*[:=]\s*\S+", "[REDACTED:PASSWORD]"),
            (r"(?:postgres|mysql|mongodb)://[^\s]+", "[REDACTED:CONNECTION_STRING]"),
            (r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b", "[REDACTED:SSN]"),
            (r"@internal\.\w+\.\w+", "[REDACTED:INTERNAL_EMAIL]"),
        ]
        
        for pattern, replacement in sensitive_patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        return result


def enforce_policy(
    user_input: str,
    response: str,
    dlp_findings: Optional[list[DLPFinding]] = None,
    engine: Optional[PolicyEngine] = None,
) -> tuple[bool, str, list[PolicyViolation]]:
    """
    Convenience function to enforce policies.
    
    Args:
        user_input: User's message.
        response: LLM's response.
        dlp_findings: DLP scan findings.
        engine: Optional custom policy engine.
        
    Returns:
        Tuple of (is_allowed, safe_response, violations)
    """
    engine = engine or PolicyEngine()
    return engine.enforce(user_input, response, dlp_findings)

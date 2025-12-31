"""
Data models for the AI Red Team Simulation framework.

Provides type-safe dataclasses for test cases, results, and configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from datetime import datetime


class AttackKind(str, Enum):
    """Types of adversarial attacks supported by the framework."""
    
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    DATA_LEAKAGE = "data_leakage"
    
    @classmethod
    def from_string(cls, value: str) -> "AttackKind":
        """Parse attack kind from string, case-insensitive."""
        normalized = value.lower().strip()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown attack kind: {value}")


class Severity(str, Enum):
    """Severity levels for security findings."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExpectedResult:
    """Expected outcome for a test case."""
    
    attack_succeeds: Optional[bool] = None
    leak_detected: Optional[bool] = None
    injection_detected: Optional[bool] = None
    contains_pattern: Optional[str] = None


@dataclass
class TestCase:
    """A single test case in a security suite."""
    
    id: str
    kind: AttackKind
    user_input: str
    notes: str = ""
    expected: Optional[ExpectedResult] = None
    rag_documents: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        if isinstance(self.kind, str):
            self.kind = AttackKind.from_string(self.kind)


@dataclass
class TargetConfig:
    """Configuration for the target application under test."""
    
    name: str
    backend: str = "mock"
    enable_mitigations: bool = False
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class SuiteConfig:
    """Configuration for a test suite."""
    
    name: str
    target: TargetConfig
    cases: list[TestCase]
    description: str = ""
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DLPFinding:
    """A data leakage finding from DLP scanning."""
    
    type: str  # e.g., "api_key", "email", "phone", "env_secret"
    value: str
    pattern: str
    severity: Severity
    start_pos: int
    end_pos: int


@dataclass
class InjectionFinding:
    """A prompt injection detection finding."""
    
    detected: bool
    reasons: list[str] = field(default_factory=list)
    patterns_matched: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class PolicyViolation:
    """A policy enforcement violation."""
    
    rule: str
    description: str
    severity: Severity


@dataclass
class MitigationResult:
    """Results from applying mitigations."""
    
    input_sanitized: bool = False
    output_sanitized: bool = False
    blocked: bool = False
    dlp_findings: list[DLPFinding] = field(default_factory=list)
    injection_finding: Optional[InjectionFinding] = None
    policy_violations: list[PolicyViolation] = field(default_factory=list)
    safe_response: Optional[str] = None


@dataclass
class TestResult:
    """Result of executing a single test case."""
    
    test_id: str
    kind: AttackKind
    user_input: str
    
    # Raw outputs
    raw_prompt: str = ""
    raw_response: str = ""
    final_response: str = ""
    
    # Scoring results
    attack_success: bool = False
    leak_detected: bool = False
    injection_detected: bool = False
    severity: Severity = Severity.LOW
    
    # Detailed findings
    mitigation_result: Optional[MitigationResult] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    
    # Execution metadata
    mitigations_enabled: bool = False
    execution_time_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class SuiteMetrics:
    """Aggregated metrics for a test suite execution."""
    
    total_cases: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    leaks_detected: int = 0
    injections_detected: int = 0
    
    # Attack Success Rate (ASR)
    overall_asr: float = 0.0
    asr_by_kind: dict[str, float] = field(default_factory=dict)
    
    # Leak type counts
    leak_types: dict[str, int] = field(default_factory=dict)
    
    # Severity distribution
    severity_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class SuiteResult:
    """Complete result of executing a test suite."""
    
    suite_name: str
    target_name: str
    mitigations_enabled: bool
    
    results: list[TestResult]
    metrics: SuiteMetrics
    
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    errors: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "suite_name": self.suite_name,
            "target_name": self.target_name,
            "mitigations_enabled": self.mitigations_enabled,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "metrics": {
                "total_cases": self.metrics.total_cases,
                "successful_attacks": self.metrics.successful_attacks,
                "failed_attacks": self.metrics.failed_attacks,
                "leaks_detected": self.metrics.leaks_detected,
                "injections_detected": self.metrics.injections_detected,
                "overall_asr": self.metrics.overall_asr,
                "asr_by_kind": self.metrics.asr_by_kind,
                "leak_types": self.metrics.leak_types,
                "severity_counts": self.metrics.severity_counts,
            },
            "results": [
                {
                    "test_id": r.test_id,
                    "kind": r.kind.value,
                    "user_input": r.user_input,
                    "raw_response": r.raw_response,
                    "final_response": r.final_response,
                    "attack_success": r.attack_success,
                    "leak_detected": r.leak_detected,
                    "injection_detected": r.injection_detected,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "mitigations_enabled": r.mitigations_enabled,
                    "execution_time_ms": r.execution_time_ms,
                    "error": r.error,
                }
                for r in self.results
            ],
            "errors": self.errors,
        }

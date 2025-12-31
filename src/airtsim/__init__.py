"""
AI Red Team Simulation (airtsim)
================================

A comprehensive LLM application security testing framework that simulates
adversarial attacks against AI-powered applications.

Key Features:
- Prompt injection testing (direct jailbreaks)
- Indirect prompt injection via RAG documents  
- Sensitive data leakage detection (secrets/PII)
- Configurable mitigations with toggle support
- Detailed reporting in Markdown and JSON formats

Usage:
    airtsim run --suite suites/demo.yaml --report-dir reports
"""

__version__ = "1.0.0"
__author__ = "Security Engineering Team"

from airtsim.models import (
    TestCase,
    TestResult,
    SuiteConfig,
    SuiteResult,
    AttackKind,
    Severity,
)

__all__ = [
    "__version__",
    "TestCase",
    "TestResult", 
    "SuiteConfig",
    "SuiteResult",
    "AttackKind",
    "Severity",
]

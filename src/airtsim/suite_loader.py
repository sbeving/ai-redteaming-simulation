"""
Suite loader for parsing YAML test suite definitions.

Handles loading, validation, and parsing of test suite YAML files
into typed dataclass structures.
"""

from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any, Optional

from airtsim.models import (
    SuiteConfig,
    TargetConfig,
    TestCase,
    ExpectedResult,
    AttackKind,
)


class SuiteLoaderError(Exception):
    """Exception raised for suite loading errors."""
    pass


class SuiteLoader:
    """
    Loads and validates test suite YAML files.
    
    Example suite format:
    ```yaml
    name: "Demo Security Suite"
    description: "Basic security test cases"
    target:
      name: rag_customer_bot
      backend: mock
      enable_mitigations: false
    cases:
      - id: test_001
        kind: prompt_injection
        user_input: "Ignore previous instructions..."
        notes: "Direct jailbreak attempt"
    ```
    """
    
    REQUIRED_SUITE_FIELDS = {"name", "target", "cases"}
    REQUIRED_TARGET_FIELDS = {"name"}
    REQUIRED_CASE_FIELDS = {"id", "kind", "user_input"}
    
    def __init__(self, strict: bool = True):
        """
        Initialize the suite loader.
        
        Args:
            strict: If True, raise on validation errors. If False, log warnings.
        """
        self.strict = strict
        self._validation_errors: list[str] = []
    
    @property
    def validation_errors(self) -> list[str]:
        """Get accumulated validation errors."""
        return self._validation_errors.copy()
    
    def load(self, path: str | Path) -> SuiteConfig:
        """
        Load a test suite from a YAML file.
        
        Args:
            path: Path to the YAML suite file.
            
        Returns:
            Parsed SuiteConfig object.
            
        Raises:
            SuiteLoaderError: If file cannot be loaded or parsed.
            FileNotFoundError: If suite file doesn't exist.
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Suite file not found: {path}")
        
        if not path.suffix.lower() in {".yaml", ".yml"}:
            raise SuiteLoaderError(f"Invalid file extension: {path.suffix}")
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise SuiteLoaderError(f"YAML parsing error: {e}") from e
        
        if not isinstance(data, dict):
            raise SuiteLoaderError("Suite file must contain a YAML mapping")
        
        return self.parse(data)
    
    def parse(self, data: dict[str, Any]) -> SuiteConfig:
        """
        Parse a dictionary into a SuiteConfig.
        
        Args:
            data: Raw dictionary from YAML.
            
        Returns:
            Validated SuiteConfig object.
        """
        self._validation_errors = []
        
        # Validate required fields
        self._validate_required_fields(data, self.REQUIRED_SUITE_FIELDS, "suite")
        
        # Parse target configuration
        target_data = data.get("target", {})
        target = self._parse_target(target_data)
        
        # Parse test cases
        cases_data = data.get("cases", [])
        cases = self._parse_cases(cases_data)
        
        if self._validation_errors and self.strict:
            errors = "\n  ".join(self._validation_errors)
            raise SuiteLoaderError(f"Suite validation failed:\n  {errors}")
        
        return SuiteConfig(
            name=data.get("name", "Unnamed Suite"),
            description=data.get("description", ""),
            version=str(data.get("version", "1.0")),
            target=target,
            cases=cases,
            metadata=data.get("metadata", {}),
        )
    
    def _parse_target(self, data: dict[str, Any]) -> TargetConfig:
        """Parse target configuration."""
        self._validate_required_fields(data, self.REQUIRED_TARGET_FIELDS, "target")
        
        return TargetConfig(
            name=data.get("name", "unknown"),
            backend=data.get("backend", "mock"),
            enable_mitigations=bool(data.get("enable_mitigations", False)),
            config=data.get("config", {}),
        )
    
    def _parse_cases(self, cases_data: list[dict]) -> list[TestCase]:
        """Parse list of test cases."""
        if not isinstance(cases_data, list):
            self._add_error("'cases' must be a list")
            return []
        
        cases = []
        seen_ids = set()
        
        for i, case_data in enumerate(cases_data):
            if not isinstance(case_data, dict):
                self._add_error(f"Case {i} must be a mapping")
                continue
            
            case = self._parse_case(case_data, i)
            if case:
                if case.id in seen_ids:
                    self._add_error(f"Duplicate case ID: {case.id}")
                else:
                    seen_ids.add(case.id)
                    cases.append(case)
        
        return cases
    
    def _parse_case(self, data: dict[str, Any], index: int) -> Optional[TestCase]:
        """Parse a single test case."""
        self._validate_required_fields(
            data, self.REQUIRED_CASE_FIELDS, f"case[{index}]"
        )
        
        case_id = data.get("id", f"case_{index}")
        
        # Parse attack kind
        kind_str = data.get("kind", "prompt_injection")
        try:
            kind = AttackKind.from_string(kind_str)
        except ValueError as e:
            self._add_error(f"Case '{case_id}': {e}")
            kind = AttackKind.PROMPT_INJECTION
        
        # Parse expected results if present
        expected = None
        if "expected" in data:
            expected = self._parse_expected(data["expected"], case_id)
        
        # Parse RAG documents for indirect injection
        rag_docs = data.get("rag_documents", [])
        if isinstance(rag_docs, str):
            rag_docs = [rag_docs]
        
        return TestCase(
            id=case_id,
            kind=kind,
            user_input=data.get("user_input", ""),
            notes=data.get("notes", ""),
            expected=expected,
            rag_documents=rag_docs,
            metadata=data.get("metadata", {}),
        )
    
    def _parse_expected(
        self, data: dict[str, Any], case_id: str
    ) -> Optional[ExpectedResult]:
        """Parse expected result configuration."""
        if not isinstance(data, dict):
            self._add_error(f"Case '{case_id}': 'expected' must be a mapping")
            return None
        
        return ExpectedResult(
            attack_succeeds=data.get("attack_succeeds"),
            leak_detected=data.get("leak_detected"),
            injection_detected=data.get("injection_detected"),
            contains_pattern=data.get("contains_pattern"),
        )
    
    def _validate_required_fields(
        self, data: dict, required: set[str], context: str
    ) -> None:
        """Check for required fields and record errors."""
        missing = required - set(data.keys())
        for field in missing:
            self._add_error(f"{context} missing required field: '{field}'")
    
    def _add_error(self, message: str) -> None:
        """Add a validation error."""
        self._validation_errors.append(message)


def load_suite(path: str | Path, strict: bool = True) -> SuiteConfig:
    """
    Convenience function to load a suite file.
    
    Args:
        path: Path to YAML suite file.
        strict: Raise on validation errors.
        
    Returns:
        Parsed SuiteConfig.
    """
    loader = SuiteLoader(strict=strict)
    return loader.load(path)

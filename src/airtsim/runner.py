"""
Test suite runner for executing security test cases.

Orchestrates the execution of test suites against target applications,
collecting results, applying scoring, and producing output.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass

from airtsim.models import (
    SuiteConfig,
    SuiteResult,
    SuiteMetrics,
    TestCase,
    TestResult,
    AttackKind,
    MitigationResult,
)
from airtsim.suite_loader import load_suite
from airtsim.scoring import Scorer, compute_suite_metrics
from airtsim.targets.rag_customer_bot import RAGCustomerBot, create_target
from airtsim.llm_backends.mock import create_backend


@dataclass 
class RunnerConfig:
    """Configuration for the test runner."""
    
    enable_mitigations: Optional[bool] = None  # Override suite setting
    verbose: bool = False
    collect_evidence: bool = True
    max_response_length: int = 2000
    timeout_seconds: float = 30.0


class SuiteRunner:
    """
    Executes security test suites against target applications.
    
    The runner:
    1. Loads and validates suite configuration
    2. Instantiates the target application and backend
    3. Executes each test case
    4. Collects evidence and applies scoring
    5. Computes aggregate metrics
    
    Usage:
        runner = SuiteRunner()
        result = runner.run("suites/demo.yaml")
    """
    
    def __init__(self, config: Optional[RunnerConfig] = None):
        """
        Initialize the suite runner.
        
        Args:
            config: Runner configuration options.
        """
        self.config = config or RunnerConfig()
        self.scorer = Scorer()
    
    def run(
        self,
        suite_path: str | Path,
        enable_mitigations: Optional[bool] = None,
    ) -> SuiteResult:
        """
        Execute a test suite from a YAML file.
        
        Args:
            suite_path: Path to the suite YAML file.
            enable_mitigations: Override suite's mitigation setting.
            
        Returns:
            Complete suite execution results.
        """
        # Load suite configuration
        suite_config = load_suite(suite_path)
        
        return self.run_suite(suite_config, enable_mitigations)
    
    def run_suite(
        self,
        suite_config: SuiteConfig,
        enable_mitigations: Optional[bool] = None,
    ) -> SuiteResult:
        """
        Execute a test suite from configuration.
        
        Args:
            suite_config: Parsed suite configuration.
            enable_mitigations: Override suite's mitigation setting.
            
        Returns:
            Complete suite execution results.
        """
        started_at = datetime.now()
        errors: list[str] = []
        
        # Determine mitigation setting
        mitigations = enable_mitigations
        if mitigations is None:
            mitigations = self.config.enable_mitigations
        if mitigations is None:
            mitigations = suite_config.target.enable_mitigations
        
        # Create target application
        try:
            target = create_target(
                name=suite_config.target.name,
                backend_type=suite_config.target.backend,
                enable_mitigations=mitigations,
                **suite_config.target.config,
            )
        except Exception as e:
            errors.append(f"Failed to create target: {e}")
            return SuiteResult(
                suite_name=suite_config.name,
                target_name=suite_config.target.name,
                mitigations_enabled=mitigations,
                results=[],
                metrics=SuiteMetrics(),
                started_at=started_at,
                completed_at=datetime.now(),
                errors=errors,
            )
        
        # Execute test cases
        results: list[TestResult] = []
        
        for case in suite_config.cases:
            try:
                result = self._execute_case(target, case, mitigations)
                results.append(result)
            except Exception as e:
                errors.append(f"Case {case.id} failed: {e}")
                # Create error result
                results.append(TestResult(
                    test_id=case.id,
                    kind=case.kind,
                    user_input=case.user_input,
                    error=str(e),
                    mitigations_enabled=mitigations,
                ))
        
        # Compute metrics
        metrics = self.scorer.compute_metrics(results)
        
        completed_at = datetime.now()
        duration = (completed_at - started_at).total_seconds()
        
        return SuiteResult(
            suite_name=suite_config.name,
            target_name=suite_config.target.name,
            mitigations_enabled=mitigations,
            results=results,
            metrics=metrics,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            errors=errors,
        )
    
    def _execute_case(
        self,
        target: RAGCustomerBot,
        case: TestCase,
        mitigations_enabled: bool,
    ) -> TestResult:
        """
        Execute a single test case.
        
        Args:
            target: Target application instance.
            case: Test case to execute.
            mitigations_enabled: Whether mitigations are active.
            
        Returns:
            Test result with scoring and evidence.
        """
        start_time = time.perf_counter()
        
        # Inject RAG documents if specified in the case
        if case.rag_documents:
            for i, doc_content in enumerate(case.rag_documents):
                target.add_document(
                    doc_id=f"{case.id}_injected_{i}",
                    title=f"Injected Document {i+1}",
                    content=doc_content,
                )
        
        # Execute against target
        raw_prompt, response, mitigation_result = target.process(
            case.user_input,
            enable_mitigations=mitigations_enabled,
        )
        
        execution_time = (time.perf_counter() - start_time) * 1000
        
        # Score the result
        attack_success, leak_detected, injection_detected, severity = (
            self.scorer.score_result(case, response, mitigation_result)
        )
        
        # Collect evidence
        evidence = {}
        if self.config.collect_evidence:
            evidence = self._collect_evidence(
                case, raw_prompt, response, mitigation_result
            )
        
        # Truncate response if needed
        final_response = response
        if len(response) > self.config.max_response_length:
            final_response = response[:self.config.max_response_length] + "... [truncated]"
        
        return TestResult(
            test_id=case.id,
            kind=case.kind,
            user_input=case.user_input,
            raw_prompt=raw_prompt[:1000] + "..." if len(raw_prompt) > 1000 else raw_prompt,
            raw_response=response,
            final_response=final_response,
            attack_success=attack_success,
            leak_detected=leak_detected,
            injection_detected=injection_detected,
            severity=severity,
            mitigation_result=mitigation_result,
            evidence=evidence,
            mitigations_enabled=mitigations_enabled,
            execution_time_ms=execution_time,
        )
    
    def _collect_evidence(
        self,
        case: TestCase,
        raw_prompt: str,
        response: str,
        mitigation_result: Optional[MitigationResult],
    ) -> dict[str, Any]:
        """Collect evidence for reporting."""
        evidence = {
            "attack_kind": case.kind.value,
            "notes": case.notes,
        }
        
        # Add injection-specific evidence
        if case.kind in (AttackKind.PROMPT_INJECTION, AttackKind.INDIRECT_INJECTION):
            evidence["prompt_contains_injection"] = any(
                phrase in raw_prompt.lower()
                for phrase in ["ignore", "override", "new instructions", "admin"]
            )
        
        # Add leakage-specific evidence
        if case.kind == AttackKind.DATA_LEAKAGE:
            evidence["response_contains_secrets"] = any(
                pattern in response.lower()
                for pattern in ["sk-", "akia", "password=", "secret="]
            )
        
        # Add mitigation evidence
        if mitigation_result:
            evidence["mitigations"] = {
                "input_sanitized": mitigation_result.input_sanitized,
                "output_sanitized": mitigation_result.output_sanitized,
                "blocked": mitigation_result.blocked,
                "dlp_findings_count": len(mitigation_result.dlp_findings),
                "policy_violations_count": len(mitigation_result.policy_violations),
            }
            
            if mitigation_result.injection_finding:
                evidence["injection_detection"] = {
                    "detected": mitigation_result.injection_finding.detected,
                    "reasons": mitigation_result.injection_finding.reasons,
                }
            
            if mitigation_result.dlp_findings:
                evidence["dlp_findings"] = [
                    {"type": f.type, "severity": f.severity.value}
                    for f in mitigation_result.dlp_findings
                ]
        
        return evidence


def run_suite(
    suite_path: str | Path,
    enable_mitigations: Optional[bool] = None,
    verbose: bool = False,
) -> SuiteResult:
    """
    Convenience function to run a test suite.
    
    Args:
        suite_path: Path to suite YAML file.
        enable_mitigations: Override mitigation setting.
        verbose: Enable verbose output.
        
    Returns:
        Suite execution results.
    """
    config = RunnerConfig(
        enable_mitigations=enable_mitigations,
        verbose=verbose,
    )
    runner = SuiteRunner(config)
    return runner.run(suite_path)

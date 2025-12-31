"""
Unit tests for suite_loader module.
"""

import pytest
import tempfile
import os
from pathlib import Path

from airtsim.suite_loader import SuiteLoader
from airtsim.models import AttackKind, Severity


class TestSuiteLoader:
    """Tests for the SuiteLoader class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.loader = SuiteLoader()
    
    def test_load_valid_suite(self, tmp_path):
        """Test loading a valid YAML suite."""
        suite_content = """
name: "test_suite"
description: "Test suite description"
version: "1.0"

config:
  target: "rag_customer_bot"
  llm_backend: "mock"

tests:
  - id: "TEST-001"
    name: "Test case 1"
    kind: "prompt_injection"
    severity: "high"
    input: "Test input"
"""
        suite_file = tmp_path / "test_suite.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert config.name == "test_suite"
        assert config.description == "Test suite description"
        assert config.target == "rag_customer_bot"
        assert len(test_cases) == 1
        assert test_cases[0].test_id == "TEST-001"
        assert test_cases[0].kind == AttackKind.PROMPT_INJECTION
        assert test_cases[0].severity == Severity.HIGH
    
    def test_load_multiple_test_cases(self, tmp_path):
        """Test loading suite with multiple test cases."""
        suite_content = """
name: "multi_test"
config:
  target: "rag_customer_bot"
tests:
  - id: "T1"
    name: "Test 1"
    kind: "prompt_injection"
    severity: "low"
    input: "Input 1"
  - id: "T2"
    name: "Test 2"
    kind: "indirect_injection"
    severity: "medium"
    input: "Input 2"
  - id: "T3"
    name: "Test 3"
    kind: "data_leakage"
    severity: "critical"
    input: "Input 3"
"""
        suite_file = tmp_path / "multi.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert len(test_cases) == 3
        assert test_cases[0].kind == AttackKind.PROMPT_INJECTION
        assert test_cases[1].kind == AttackKind.INDIRECT_INJECTION
        assert test_cases[2].kind == AttackKind.DATA_LEAKAGE
    
    def test_load_suite_with_rag_context(self, tmp_path):
        """Test loading suite with RAG document context."""
        suite_content = """
name: "rag_test"
config:
  target: "rag_customer_bot"
tests:
  - id: "RAG-001"
    name: "RAG injection test"
    kind: "indirect_injection"
    severity: "high"
    input: "What's in the knowledge base?"
    context:
      rag_docs:
        - source: "doc1.txt"
          content: "Document 1 content"
        - source: "doc2.txt"
          content: "Document 2 content"
"""
        suite_file = tmp_path / "rag_suite.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert len(test_cases) == 1
        assert test_cases[0].context is not None
        assert "rag_docs" in test_cases[0].context
        assert len(test_cases[0].context["rag_docs"]) == 2
    
    def test_load_missing_file(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            self.loader.load("/nonexistent/path/suite.yaml")
    
    def test_load_invalid_yaml(self, tmp_path):
        """Test error handling for invalid YAML."""
        suite_file = tmp_path / "invalid.yaml"
        suite_file.write_text("{ invalid yaml: [")
        
        with pytest.raises(Exception):
            self.loader.load(str(suite_file))
    
    def test_load_missing_required_fields(self, tmp_path):
        """Test validation catches missing required fields."""
        suite_content = """
name: "incomplete"
config:
  target: "rag_customer_bot"
tests:
  - id: "T1"
    # Missing: name, kind, severity, input
"""
        suite_file = tmp_path / "incomplete.yaml"
        suite_file.write_text(suite_content)
        
        with pytest.raises(ValueError, match="Missing required field"):
            self.loader.load(str(suite_file))
    
    def test_load_invalid_attack_kind(self, tmp_path):
        """Test validation catches invalid attack kind."""
        suite_content = """
name: "invalid_kind"
config:
  target: "rag_customer_bot"
tests:
  - id: "T1"
    name: "Test"
    kind: "invalid_attack_type"
    severity: "high"
    input: "Test"
"""
        suite_file = tmp_path / "invalid_kind.yaml"
        suite_file.write_text(suite_content)
        
        with pytest.raises(ValueError, match="Invalid attack kind"):
            self.loader.load(str(suite_file))
    
    def test_load_invalid_severity(self, tmp_path):
        """Test validation catches invalid severity."""
        suite_content = """
name: "invalid_severity"
config:
  target: "rag_customer_bot"
tests:
  - id: "T1"
    name: "Test"
    kind: "prompt_injection"
    severity: "super_critical"
    input: "Test"
"""
        suite_file = tmp_path / "invalid_sev.yaml"
        suite_file.write_text(suite_content)
        
        with pytest.raises(ValueError, match="Invalid severity"):
            self.loader.load(str(suite_file))
    
    def test_expected_behavior_parsing(self, tmp_path):
        """Test parsing of expected behavior specifications."""
        suite_content = """
name: "behavior_test"
config:
  target: "rag_customer_bot"
tests:
  - id: "B1"
    name: "Behavior test"
    kind: "prompt_injection"
    severity: "high"
    input: "Test input"
    expected_behavior:
      - type: "block"
        description: "Should be blocked"
      - type: "contain"
        pattern: "I cannot"
"""
        suite_file = tmp_path / "behavior.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert test_cases[0].expected_behavior is not None
        assert len(test_cases[0].expected_behavior) == 2
    
    def test_suite_config_defaults(self, tmp_path):
        """Test default values in suite config."""
        suite_content = """
name: "minimal"
tests:
  - id: "M1"
    name: "Minimal test"
    kind: "prompt_injection"
    severity: "low"
    input: "Test"
"""
        suite_file = tmp_path / "minimal.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert config.target == "rag_customer_bot"  # default
        assert config.llm_backend == "mock"  # default


class TestSuiteLoaderEdgeCases:
    """Edge case tests for SuiteLoader."""
    
    def setup_method(self):
        self.loader = SuiteLoader()
    
    def test_empty_tests_list(self, tmp_path):
        """Test handling of empty tests list."""
        suite_content = """
name: "empty"
config:
  target: "rag_customer_bot"
tests: []
"""
        suite_file = tmp_path / "empty.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        assert len(test_cases) == 0
    
    def test_multiline_input(self, tmp_path):
        """Test handling of multiline input strings."""
        suite_content = """
name: "multiline"
config:
  target: "rag_customer_bot"
tests:
  - id: "ML1"
    name: "Multiline test"
    kind: "prompt_injection"
    severity: "high"
    input: |
      This is a multiline
      test input with
      several lines.
"""
        suite_file = tmp_path / "multiline.yaml"
        suite_file.write_text(suite_content)
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert "multiline" in test_cases[0].user_input
        assert "several lines" in test_cases[0].user_input
    
    def test_unicode_content(self, tmp_path):
        """Test handling of unicode content."""
        suite_content = """
name: "unicode_test"
config:
  target: "rag_customer_bot"
tests:
  - id: "U1"
    name: "Unicode test 日本語"
    kind: "prompt_injection"
    severity: "medium"
    input: "Test with émojis 🎉 and spëcial çharacters"
"""
        suite_file = tmp_path / "unicode.yaml"
        suite_file.write_text(suite_content, encoding="utf-8")
        
        config, test_cases = self.loader.load(str(suite_file))
        
        assert "日本語" in test_cases[0].name
        assert "🎉" in test_cases[0].user_input

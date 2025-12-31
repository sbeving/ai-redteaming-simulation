"""
LLM Backend package for AI Red Team Simulation.

Provides different backend implementations for LLM interactions,
including mock backends for deterministic testing.
"""

from airtsim.llm_backends.mock import MockLLMBackend

__all__ = ["MockLLMBackend"]

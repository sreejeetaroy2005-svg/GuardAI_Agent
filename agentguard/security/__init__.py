"""
Security sub-package for AgentGuard.
Provides untrusted-input scanning and prompt-injection detection.
"""

from agentguard.security.input_guard import InjectionScanResult, UntrustedInputGuard

__all__ = ["UntrustedInputGuard", "InjectionScanResult"]

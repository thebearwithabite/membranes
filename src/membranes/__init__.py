"""
membranes - Prompt Injection Defense for AI Agents
===================================================

A semi-permeable barrier between your AI and the world.
Scans content for prompt injection attacks before they reach your agent's context.

Usage:
    from membranes import Scanner
    
    scanner = Scanner()
    result = scanner.scan("Some potentially dangerous content")
    
    if result.is_safe:
        # Content is clean, pass to agent
        pass
    else:
        # Content contains threats
        print(f"Blocked: {result.threats}")

MIT License - https://github.com/membranes/membranes
"""

__version__ = "0.2.0"
__author__ = "Cosmo & Ryan"

from .scanner import Scanner, ScanResult, Threat
from .sanitizer import Sanitizer
from .threat_logger import ThreatLogger, ThreatEntry, log_threat, get_logger

__all__ = [
    "Scanner", "ScanResult", "Threat", "Sanitizer",
    "ThreatLogger", "ThreatEntry", "log_threat", "get_logger"
]

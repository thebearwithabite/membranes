"""
membranes.threat_logger - Crowdsourced threat intelligence
==========================================================

"You cannot sue a stone nor skip the gate of accountability."

Logs detected threats for analysis and optional sharing with the
membranes threat intelligence network.

Usage:
    from membranes import Scanner, ThreatLogger
    
    scanner = Scanner()
    logger = ThreatLogger(contribute=True)  # Opt-in to share anonymized data
    
    result = scanner.scan(content)
    if not result.is_safe:
        logger.log(result)
    
    # View local threat log
    for entry in logger.get_entries():
        print(entry)
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any, Iterator
import threading


@dataclass
class ThreatEntry:
    """A logged threat event."""
    
    # Identity (anonymized)
    payload_hash: str          # SHA256 of the raw payload
    short_hash: str            # First 8 chars for display
    
    # Classification
    threat_names: List[str]    # e.g., ["jailbreak_attempt", "role_override"]
    categories: List[str]      # e.g., ["jailbreak", "hidden_payload"]
    max_severity: str          # critical, high, medium, low
    
    # Detection metadata
    obfuscation_methods: List[str]  # e.g., ["base64", "unicode_hidden"]
    pattern_matches: int       # How many patterns triggered
    
    # Context (no PII)
    timestamp: str             # ISO format UTC
    timestamp_unix: float      # For sorting
    content_length: int        # Size of original content
    scan_time_ms: float        # Detection performance
    
    # Telemetry (if contributed)
    instance_id: Optional[str] = None  # Anonymous install ID
    contributed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatEntry":
        return cls(**data)
    
    def summary(self) -> str:
        """Human-readable one-liner."""
        return (
            f"[{self.short_hash}] {self.max_severity.upper()} "
            f"{', '.join(self.threat_names[:3])} "
            f"via {', '.join(self.obfuscation_methods) or 'plain'} "
            f"@ {self.timestamp}"
        )


class ThreatLogger:
    """
    Logs detected threats locally and optionally contributes to 
    the global membranes threat intelligence network.
    
    Args:
        log_dir: Directory to store local logs. Defaults to ~/.membranes/threats/
        contribute: If True, anonymized threat data is sent to the central aggregator
        instance_id: Anonymous identifier for this installation (auto-generated if None)
        telemetry_endpoint: URL for threat contribution (future)
    """
    
    DEFAULT_LOG_DIR = Path.home() / ".membranes" / "threats"
    TELEMETRY_ENDPOINT = "https://api.membranes.dev/threats"  # Future
    
    def __init__(
        self,
        log_dir: Optional[str] = None,
        contribute: bool = False,
        instance_id: Optional[str] = None,
        telemetry_endpoint: Optional[str] = None
    ):
        self.log_dir = Path(log_dir) if log_dir else self.DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.contribute = contribute
        self.telemetry_endpoint = telemetry_endpoint or self.TELEMETRY_ENDPOINT
        
        # Generate or load instance ID
        self.instance_id = instance_id or self._get_instance_id()
        
        # Thread-safe file writing
        self._lock = threading.Lock()
        
        # Current log file (rotates daily)
        self._current_log_file: Optional[Path] = None
    
    def _get_instance_id(self) -> str:
        """Get or create anonymous instance identifier."""
        id_file = self.log_dir / ".instance_id"
        
        if id_file.exists():
            return id_file.read_text().strip()
        
        # Generate new anonymous ID
        instance_id = hashlib.sha256(
            f"{os.getpid()}{time.time()}{os.urandom(16).hex()}".encode()
        ).hexdigest()[:16]
        
        id_file.write_text(instance_id)
        return instance_id
    
    def _get_log_file(self) -> Path:
        """Get current log file (rotates daily)."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"threats-{today}.jsonl"
    
    def _detect_obfuscation(self, result: "ScanResult") -> List[str]:
        """Infer obfuscation methods from detected threats."""
        methods = set()
        
        for threat in result.threats:
            if "base64" in threat.name.lower():
                methods.add("base64")
            if "unicode" in threat.name.lower() or "invisible" in threat.name.lower():
                methods.add("unicode_hidden")
            if "encoded" in threat.name.lower():
                methods.add("encoding")
            if "markdown" in threat.name.lower():
                methods.add("markdown_abuse")
            if threat.category == "hidden_payload":
                methods.add("hidden_payload")
        
        return list(methods) or ["plain"]
    
    def log(self, result: "ScanResult", raw_content: Optional[str] = None) -> ThreatEntry:
        """
        Log a scan result that contains threats.
        
        Args:
            result: ScanResult from Scanner.scan()
            raw_content: Original content (for hashing, not stored)
            
        Returns:
            The created ThreatEntry
        """
        if result.is_safe:
            raise ValueError("Cannot log a safe scan result")
        
        # Hash the payload (we don't store raw content)
        if raw_content:
            payload_hash = hashlib.sha256(raw_content.encode()).hexdigest()
        else:
            payload_hash = result.content_hash + "_partial"
        
        now = datetime.now(timezone.utc)
        
        entry = ThreatEntry(
            payload_hash=payload_hash,
            short_hash=payload_hash[:8],
            threat_names=list(set(t.name for t in result.threats)),
            categories=result.categories,
            max_severity=result.max_severity or "unknown",
            obfuscation_methods=self._detect_obfuscation(result),
            pattern_matches=result.threat_count,
            timestamp=now.isoformat(),
            timestamp_unix=now.timestamp(),
            content_length=result.metadata.get("content_length", 0),
            scan_time_ms=result.scan_time_ms,
            instance_id=self.instance_id if self.contribute else None,
            contributed=False
        )
        
        # Write to local log
        self._write_entry(entry)
        
        # Contribute to network if enabled
        if self.contribute:
            self._contribute(entry)
        
        return entry
    
    def _write_entry(self, entry: ThreatEntry) -> None:
        """Write entry to local JSONL log."""
        with self._lock:
            log_file = self._get_log_file()
            with open(log_file, "a") as f:
                f.write(entry.to_json() + "\n")
    
    def _contribute(self, entry: ThreatEntry) -> bool:
        """
        Send anonymized threat data to central aggregator.
        
        Returns True if successfully contributed.
        """
        # TODO: Implement actual HTTP POST to telemetry endpoint
        # For now, just mark as contributed
        entry.contributed = True
        
        # Future implementation:
        # try:
        #     import urllib.request
        #     data = json.dumps(entry.to_dict()).encode()
        #     req = urllib.request.Request(
        #         self.telemetry_endpoint,
        #         data=data,
        #         headers={"Content-Type": "application/json"}
        #     )
        #     urllib.request.urlopen(req, timeout=5)
        #     return True
        # except Exception:
        #     return False
        
        return True
    
    def get_entries(
        self,
        days: int = 7,
        min_severity: Optional[str] = None,
        category: Optional[str] = None
    ) -> Iterator[ThreatEntry]:
        """
        Iterate over logged threat entries.
        
        Args:
            days: Number of days of history to include
            min_severity: Minimum severity level to include
            category: Filter to specific category
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev = severity_order.get(min_severity, 0) if min_severity else 0
        
        # Find log files in date range
        from datetime import timedelta
        
        for i in range(days):
            date = datetime.now(timezone.utc) - timedelta(days=i)
            log_file = self.log_dir / f"threats-{date.strftime('%Y-%m-%d')}.jsonl"
            
            if not log_file.exists():
                continue
            
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        entry = ThreatEntry.from_dict(json.loads(line))
                        
                        # Apply filters
                        if severity_order.get(entry.max_severity, 0) < min_sev:
                            continue
                        if category and category not in entry.categories:
                            continue
                        
                        yield entry
                    except (json.JSONDecodeError, TypeError):
                        continue
    
    def get_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get aggregate statistics for the threat log."""
        entries = list(self.get_entries(days=days))
        
        if not entries:
            return {"total": 0, "days": days}
        
        severity_counts = {}
        category_counts = {}
        method_counts = {}
        threat_counts = {}
        
        for entry in entries:
            # Severity
            sev = entry.max_severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Categories
            for cat in entry.categories:
                category_counts[cat] = category_counts.get(cat, 0) + 1
            
            # Obfuscation methods
            for method in entry.obfuscation_methods:
                method_counts[method] = method_counts.get(method, 0) + 1
            
            # Specific threats
            for name in entry.threat_names:
                threat_counts[name] = threat_counts.get(name, 0) + 1
        
        return {
            "total": len(entries),
            "days": days,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "by_obfuscation": method_counts,
            "top_threats": dict(sorted(
                threat_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "unique_payloads": len(set(e.payload_hash for e in entries))
        }
    
    def export_feed(self, format: str = "json", days: int = 1) -> str:
        """
        Export threat log as RSS/JSON feed.
        
        Args:
            format: "json" or "rss"
            days: Number of days to include
        """
        entries = list(self.get_entries(days=days))
        
        if format == "json":
            return json.dumps({
                "feed": "membranes-threats",
                "version": "1.0",
                "generated": datetime.now(timezone.utc).isoformat(),
                "entries": [e.to_dict() for e in entries]
            }, indent=2)
        
        elif format == "rss":
            items = "\n".join([
                f"""    <item>
      <title>[{e.short_hash}] {e.max_severity.upper()}: {', '.join(e.threat_names[:2])}</title>
      <description>{e.summary()}</description>
      <pubDate>{e.timestamp}</pubDate>
      <guid>{e.payload_hash}</guid>
    </item>"""
                for e in entries
            ])
            
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>membranes Threat Feed</title>
    <link>https://membranes.dev/threats</link>
    <description>Crowdsourced prompt injection threat intelligence</description>
    <lastBuildDate>{datetime.now(timezone.utc).isoformat()}</lastBuildDate>
{items}
  </channel>
</rss>"""
        
        else:
            raise ValueError(f"Unknown format: {format}")


# Convenience function for quick logging
_default_logger: Optional[ThreatLogger] = None

def get_logger(contribute: bool = False) -> ThreatLogger:
    """Get or create the default threat logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = ThreatLogger(contribute=contribute)
    return _default_logger


def log_threat(result: "ScanResult", raw_content: Optional[str] = None) -> ThreatEntry:
    """Quick function to log a threat using the default logger."""
    return get_logger().log(result, raw_content)

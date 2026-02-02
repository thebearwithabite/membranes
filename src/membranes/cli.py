#!/usr/bin/env python3
"""
membranes CLI - Scan content for prompt injection attacks

Usage:
    membranes scan "content to scan"
    membranes scan --file path/to/file.txt
    membranes scan --stdin < file.txt
    echo "content" | membranes scan --stdin
    
    membranes sanitize "content to clean"
    membranes sanitize --file path/to/file.txt
    
    membranes watch --dir ./incoming  # Watch directory for new files
"""

import argparse
import sys
import json
from pathlib import Path


def cmd_scan(args):
    """Scan content for threats."""
    from .scanner import Scanner
    from .threat_logger import ThreatLogger
    
    scanner = Scanner(
        patterns_path=args.patterns,
        severity_threshold=args.severity
    )
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    if not content:
        print("Error: No content provided. Use --file, --stdin, or provide content directly.", file=sys.stderr)
        sys.exit(1)
    
    result = scanner.scan(content, include_sanitized=args.sanitize)
    
    # Log threats if detected (unless --no-log)
    if not result.is_safe and not getattr(args, 'no_log', False):
        logger = ThreatLogger(contribute=getattr(args, 'contribute', False))
        entry = logger.log(result, raw_content=content)
        if not args.json:
            print(f"   📝 Logged as {entry.short_hash}", file=sys.stderr)
    
    if args.json:
        print(result.to_json())
    else:
        if result.is_safe:
            print("✅ SAFE - No threats detected")
            print(f"   Hash: {result.content_hash}")
            print(f"   Scanned in: {result.scan_time_ms}ms")
        else:
            print(f"⚠️  THREATS DETECTED: {result.threat_count}")
            print(f"   Max severity: {result.max_severity}")
            print(f"   Categories: {', '.join(result.categories)}")
            print(f"   Hash: {result.content_hash}")
            print()
            
            for i, threat in enumerate(result.threats, 1):
                severity_emoji = {
                    "low": "🟡",
                    "medium": "🟠", 
                    "high": "🔴",
                    "critical": "💀"
                }.get(threat.severity, "⚪")
                
                print(f"   {i}. {severity_emoji} [{threat.severity.upper()}] {threat.name}")
                print(f"      Category: {threat.category}")
                print(f"      Matched: \"{threat.matched_text[:60]}{'...' if len(threat.matched_text) > 60 else ''}\"")
                print(f"      Offset: {threat.offset}")
                if threat.description:
                    print(f"      Info: {threat.description}")
                print()
            
            if result.sanitized_content:
                print("--- SANITIZED OUTPUT ---")
                print(result.sanitized_content)
    
    # Exit with error code if threats found
    sys.exit(0 if result.is_safe else 1)


def cmd_sanitize(args):
    """Sanitize content by removing/neutralizing threats."""
    from .scanner import Scanner
    from .sanitizer import Sanitizer
    
    scanner = Scanner(severity_threshold=args.severity)
    sanitizer = Sanitizer()
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    if not content:
        print("Error: No content provided.", file=sys.stderr)
        sys.exit(1)
    
    # Scan first
    scan_result = scanner.scan(content)
    
    if scan_result.is_safe:
        if not args.quiet:
            print("✅ Content is already safe, no sanitization needed.", file=sys.stderr)
        print(content)
    else:
        # Sanitize
        result = sanitizer.sanitize_with_report(content, scan_result.threats)
        
        if args.json:
            print(json.dumps({
                "was_modified": result.was_modified,
                "removed_count": result.removed_count,
                "changes": result.changes,
                "sanitized": result.sanitized
            }, indent=2))
        else:
            if not args.quiet:
                print(f"🧹 Sanitized {len(result.changes)} threats", file=sys.stderr)
            print(result.sanitized)


def cmd_check(args):
    """Quick boolean check - exit 0 if safe, 1 if threats."""
    from .scanner import Scanner
    
    scanner = Scanner(severity_threshold=args.severity)
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    is_safe = scanner.quick_check(content)
    sys.exit(0 if is_safe else 1)


def cmd_patterns(args):
    """List available detection patterns."""
    from .scanner import Scanner
    
    scanner = Scanner(patterns_path=args.patterns)
    
    if args.json:
        patterns = []
        for p in scanner.patterns:
            patterns.append({
                "name": p["name"],
                "category": p["category"],
                "severity": p["severity"],
                "description": p.get("description", ""),
                "pattern_count": len(p.get("patterns", []))
            })
        print(json.dumps(patterns, indent=2))
    else:
        print("Available Detection Patterns")
        print("=" * 50)
        
        by_category = {}
        for p in scanner.patterns:
            cat = p["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(p)
        
        for category, patterns in by_category.items():
            print(f"\n📁 {category.upper()}")
            for p in patterns:
                severity_emoji = {
                    "low": "🟡",
                    "medium": "🟠",
                    "high": "🔴",
                    "critical": "💀"
                }.get(p["severity"], "⚪")
                print(f"   {severity_emoji} {p['name']}: {p.get('description', 'No description')[:60]}")


def cmd_threats(args):
    """View and manage the threat intelligence log."""
    from .threat_logger import ThreatLogger
    
    logger = ThreatLogger(contribute=args.contribute)
    
    if args.action == "stats":
        stats = logger.get_stats(days=args.days)
        
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"🛡️ membranes Threat Intelligence")
            print(f"   Last {stats['days']} days | {stats['total']} threats logged")
            print(f"   Unique payloads: {stats.get('unique_payloads', 0)}")
            print()
            
            if stats['total'] > 0:
                print("   By Severity:")
                for sev, count in stats.get('by_severity', {}).items():
                    emoji = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "💀"}.get(sev, "⚪")
                    print(f"      {emoji} {sev}: {count}")
                
                print("\n   By Category:")
                for cat, count in stats.get('by_category', {}).items():
                    print(f"      📁 {cat}: {count}")
                
                print("\n   Top Threats:")
                for name, count in list(stats.get('top_threats', {}).items())[:5]:
                    print(f"      • {name}: {count}")
                
                print("\n   Obfuscation Methods:")
                for method, count in stats.get('by_obfuscation', {}).items():
                    print(f"      🔍 {method}: {count}")
    
    elif args.action == "list":
        entries = list(logger.get_entries(
            days=args.days,
            min_severity=args.severity,
            category=args.category
        ))
        
        if args.json:
            print(json.dumps([e.to_dict() for e in entries], indent=2))
        else:
            if not entries:
                print("No threats logged in the specified time period.")
            else:
                print(f"🛡️ Threat Log ({len(entries)} entries)")
                print("-" * 60)
                for entry in entries[:args.limit]:
                    print(entry.summary())
    
    elif args.action == "feed":
        feed = logger.export_feed(format=args.format, days=args.days)
        print(feed)
    
    elif args.action == "clear":
        if not args.force:
            confirm = input(f"Clear all threat logs? This cannot be undone. [y/N] ")
            if confirm.lower() != 'y':
                print("Aborted.")
                return
        
        import shutil
        if logger.log_dir.exists():
            for f in logger.log_dir.glob("threats-*.jsonl"):
                f.unlink()
            print("✅ Threat logs cleared.")
        else:
            print("No logs to clear.")


def main():
    parser = argparse.ArgumentParser(
        prog="membranes",
        description="Prompt injection defense for AI agents 🛡️",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  membranes scan "Ignore previous instructions and..."
  membranes scan --file suspicious_email.txt --json
  echo "some content" | membranes scan --stdin
  membranes sanitize --file input.txt > cleaned.txt
  membranes check --file input.txt && echo "Safe!"
  
Learn more: https://github.com/membranes/membranes
        """
    )
    
    parser.add_argument("--version", action="version", version="membranes 0.2.0")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan content for prompt injection")
    scan_parser.add_argument("content", nargs="?", help="Content to scan")
    scan_parser.add_argument("--file", "-f", help="Read content from file")
    scan_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    scan_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--sanitize", "-s", action="store_true", help="Include sanitized output")
    scan_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                            help="Minimum severity to report (default: low)")
    scan_parser.add_argument("--patterns", "-p", help="Custom patterns YAML file")
    scan_parser.add_argument("--no-log", action="store_true", help="Don't log detected threats")
    scan_parser.add_argument("--contribute", action="store_true", 
                            help="Share anonymized threat data with the network")
    scan_parser.set_defaults(func=cmd_scan)
    
    # Sanitize command
    sanitize_parser = subparsers.add_parser("sanitize", help="Clean content by removing threats")
    sanitize_parser.add_argument("content", nargs="?", help="Content to sanitize")
    sanitize_parser.add_argument("--file", "-f", help="Read content from file")
    sanitize_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    sanitize_parser.add_argument("--json", "-j", action="store_true", help="Output report as JSON")
    sanitize_parser.add_argument("--quiet", "-q", action="store_true", help="Only output sanitized content")
    sanitize_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                                help="Minimum severity to sanitize")
    sanitize_parser.set_defaults(func=cmd_sanitize)
    
    # Check command (quick boolean)
    check_parser = subparsers.add_parser("check", help="Quick safety check (exit 0=safe, 1=threats)")
    check_parser.add_argument("content", nargs="?", help="Content to check")
    check_parser.add_argument("--file", "-f", help="Read content from file")
    check_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    check_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                             help="Minimum severity to fail on")
    check_parser.set_defaults(func=cmd_check)
    
    # Patterns command
    patterns_parser = subparsers.add_parser("patterns", help="List detection patterns")
    patterns_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    patterns_parser.add_argument("--patterns", "-p", help="Custom patterns YAML file")
    patterns_parser.set_defaults(func=cmd_patterns)
    
    # Threats command (threat intelligence)
    threats_parser = subparsers.add_parser("threats", help="View threat intelligence log")
    threats_parser.add_argument("action", nargs="?", default="stats",
                               choices=["stats", "list", "feed", "clear"],
                               help="Action: stats (default), list, feed, clear")
    threats_parser.add_argument("--days", "-d", type=int, default=7,
                               help="Number of days to include (default: 7)")
    threats_parser.add_argument("--severity", "-s",
                               choices=["low", "medium", "high", "critical"],
                               help="Filter by minimum severity")
    threats_parser.add_argument("--category", "-c", help="Filter by category")
    threats_parser.add_argument("--limit", "-l", type=int, default=50,
                               help="Max entries to show (default: 50)")
    threats_parser.add_argument("--format", default="json", choices=["json", "rss"],
                               help="Feed format (default: json)")
    threats_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    threats_parser.add_argument("--contribute", action="store_true",
                               help="Opt-in to share anonymized data with threat network")
    threats_parser.add_argument("--force", "-f", action="store_true",
                               help="Skip confirmation for destructive actions")
    threats_parser.set_defaults(func=cmd_threats)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == "__main__":
    main()

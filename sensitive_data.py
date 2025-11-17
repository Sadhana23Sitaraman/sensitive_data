#!/usr/bin/env python3
"""
sensitive_filter.py

Usage:
    - Programmatic:
        from sensitive_filter import SensitiveFilter
        sf = SensitiveFilter()
        results = sf.scan(text)
        redacted = sf.redact(text)

    - CLI:
        python sensitive_filter.py --input example.txt --redact --report report.json
"""

from dataclasses import dataclass, asdict
import re
import hashlib
import json
import argparse
import math
from typing import List, Pattern, Dict, Any, Tuple

# -------------------------
# Utilities
# -------------------------
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def deterministic_mask(token: str, salt: str = 'sensitive') -> str:
    """Create a deterministic short hash to replace secrets while preserving uniqueness."""
    h = hashlib.sha256((salt + token).encode('utf-8')).hexdigest()
    return f"<REDACTED_{h[:12]}>"

# -------------------------
# Patterns - customizable
# -------------------------
@dataclass
class PatternDef:
    name: str
    regex: Pattern
    severity: int = 5
    description: str = ""

DEFAULT_PATTERNS: List[PatternDef] = [
    PatternDef(
        name="EMAIL",
        regex=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        severity=3,
        description="Email address"
    ),
    PatternDef(
        name="US_PHONE",
        regex=re.compile(r'\b(?:\+1[-.\s]?)*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        severity=4,
        description="US-style phone number"
    ),
    PatternDef(
        name="SSN",
        regex=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        severity=8,
        description="US Social Security Number"
    ),
    PatternDef(
        name="CREDIT_CARD",
        regex=re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        severity=9,
        description="Potential credit card number (Luhn not applied)"
    ),
    PatternDef(
        name="BASIC_AUTH",
        regex=re.compile(r'\b[A-Za-z0-9._%+-]+:[A-Za-z0-9@#$%^&*()_+\-=\[\]{};\'",.<>/?\\|`~]{6,}\b'),
        severity=9,
        description="Username:Password style credential"
    ),
    PatternDef(
        name="AWS_ACCESS_KEY_ID",
        regex=re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        severity=10,
        description="AWS access key id"
    ),
    PatternDef(
        name="AWS_SECRET_ACCESS_KEY",
        regex=re.compile(r'\b(?:[A-Za-z0-9/+=]{40})\b'),
        severity=10,
        description="AWS secret (40 char base64-like)"
    ),
    PatternDef(
        name="JWT",
        regex=re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b'),
        severity=10,
        description="JSON Web Token (header.payload.signature)"
    ),
    PatternDef(
        name="PRIVATE_KEY_BLOCK",
        regex=re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END (?:RSA|EC|OPENSSH|PRIVATE) KEY-----'),
        severity=10,
        description="PEM private key block"
    ),
    PatternDef(
        name="GENERIC_API_KEY",
        regex=re.compile(r'\b(?:api_key|apikey|key|secret|token)[\s:=]{1,4}[A-Za-z0-9\-\._]{16,}\b', re.IGNORECASE),
        severity=9,
        description="Generic key-like token assignment (heuristic)"
    ),
    # Add more domain-specific patterns as necessary
]

# -------------------------
# Detection / Redaction
# -------------------------
@dataclass
class Finding:
    pattern_name: str
    match: str
    start: int
    end: int
    severity: int
    description: str
    entropy: float = 0.0
    redaction: str = ""

class SensitiveFilter:
    def __init__(self, patterns: List[PatternDef] = None, entropy_threshold: float = 4.0):
        self.patterns = patterns or DEFAULT_PATTERNS
        self.entropy_threshold = entropy_threshold

    def scan(self, text: str) -> List[Finding]:
        """Scan text and return list of findings with metadata."""
        findings: List[Finding] = []
        for p in self.patterns:
            for m in p.regex.finditer(text):
                token = m.group(0)
                ent = shannon_entropy(token)
                # Additional heuristic: for generic tokens, only flag if high entropy or long length
                if p.name == "GENERIC_API_KEY" and ent < self.entropy_threshold and len(token) < 30:
                    # skip if not high-entropy and not long
                    continue
                finding = Finding(
                    pattern_name=p.name,
                    match=token,
                    start=m.start(),
                    end=m.end(),
                    severity=p.severity,
                    description=p.description,
                    entropy=ent
                )
                findings.append(finding)
        # Sort findings by start index
        findings.sort(key=lambda f: f.start)
        return findings

    def redact(self, text: str, mask_with_hash: bool = True, preserve_prefix: int = 0) -> Tuple[str, List[Finding]]:
        """
        Redact findings in text.

        - mask_with_hash: replace each secret with a deterministic masked token (keeps unique mapping)
        - preserve_prefix: keep the first N characters of the token visible (useful for debugging)
        Returns redacted text and the findings (findings have redaction field set).
        """
        findings = self.scan(text)
        if not findings:
            return text, findings

        parts: List[str] = []
        last_idx = 0

        for f in findings:
            parts.append(text[last_idx:f.start])
            token = f.match
            if preserve_prefix > 0 and len(token) > preserve_prefix:
                visible = token[:preserve_prefix]
                secret_part = token[preserve_prefix:]
            else:
                visible = ""
                secret_part = token

            if mask_with_hash:
                masked = deterministic_mask(secret_part)
                redaction = visible + masked
            else:
                redaction = visible + "<REDACTED>"
            f.redaction = redaction
            parts.append(redaction)
            last_idx = f.end

        parts.append(text[last_idx:])
        redacted_text = "".join(parts)
        return redacted_text, findings

    def report(self, findings: List[Finding]) -> Dict[str, Any]:
        """Create summary report dictionary from findings."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            grouped.setdefault(f.pattern_name, []).append({
                "match": f.match,
                "start": f.start,
                "end": f.end,
                "severity": f.severity,
                "entropy": f.entropy,
                "description": f.description,
                "redaction": f.redaction
            })
        total = sum(len(v) for v in grouped.values())
        return {
            "total_findings": total,
            "by_pattern": grouped
        }

# -------------------------
# CLI
# -------------------------
def cli():
    parser = argparse.ArgumentParser(description="Sensitive data detector & redactor")
    parser.add_argument("--input", "-i", help="Input file (if omitted, reads stdin)", default=None)
    parser.add_argument("--output", "-o", help="Write redacted output to file (optional)")
    parser.add_argument("--redact", action="store_true", help="Perform redaction (otherwise just report findings)")
    parser.add_argument("--preserve-prefix", type=int, default=0, help="Number of prefix chars to preserve in tokens")
    parser.add_argument("--entropy", type=float, default=4.0, help="Entropy threshold for generic tokens")
    parser.add_argument("--report", help="Write JSON report to this file (optional)")
    args = parser.parse_args()

    if args.input:
        with open(args.input, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        import sys
        text = sys.stdin.read()

    sf = SensitiveFilter(entropy_threshold=args.entropy)
    if args.redact:
        redacted, findings = sf.redact(text, preserve_prefix=args.preserve_prefix)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as out:
                out.write(redacted)
            print(f"[+] Redacted output written to {args.output}")
        else:
            print(redacted)
        report = sf.report(findings)
    else:
        findings = sf.scan(text)
        report = sf.report(findings)
        print(json.dumps(report, indent=2))

    if args.report:
        with open(args.report, 'w', encoding='utf-8') as r:
            json.dump(report, r, indent=2)
        print(f"[+] Report written to {args.report}")
    else:
        print("[+] Summary:")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    cli()

"""Audit orchestration: single checks, batch audits, masked reports.

Masking: batch reports NEVER contain a full password. Two styles:

- ``partial`` (default): keep only the first and last character,
  e.g. ``"hunter2"`` -> ``"h*****2"``. Passwords of length <= 2 become
  ``"**"`` so nothing leaks.
- ``full``: every character replaced, e.g. ``"hunter2"`` -> ``"*******"``.

Strength labels from charset entropy (widely used bands):

===========  ============
< 28 bits     very weak
28-35         weak
36-59         fair
60-127        strong
>= 128        very strong
===========  ============
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import (
    charset_size,
    entropy_bits,
    shannon_entropy_per_char,
    shannon_entropy_total,
)
from .patterns import PatternFinding, find_patterns
from .policy import DEFAULT_POLICY, Policy, PolicyResult, evaluate

MASK_STYLES = ("partial", "full")


def strength_label(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 128:
        return "strong"
    return "very strong"


def mask_password(password: str, style: str = "partial") -> str:
    """Mask a password for reporting. Never returns the full password
    (except the empty string, which masks to itself)."""
    if style not in MASK_STYLES:
        raise ValueError(f"unknown mask style: {style!r} (expected {MASK_STYLES})")
    if not password:
        return ""
    if style == "full" or len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


@dataclass
class AuditResult:
    masked: str
    length: int
    charset_size: int
    entropy_bits: float
    shannon_per_char: float
    shannon_total: float
    strength: str
    patterns: list[PatternFinding] = field(default_factory=list)
    policy: PolicyResult | None = None

    def to_dict(self) -> dict:
        return {
            "masked": self.masked,
            "length": self.length,
            "charset_size": self.charset_size,
            "entropy_bits": round(self.entropy_bits, 2),
            "shannon_per_char": round(self.shannon_per_char, 4),
            "shannon_total": round(self.shannon_total, 2),
            "strength": self.strength,
            "patterns": [
                {"kind": p.kind, "detail": p.detail} for p in self.patterns
            ],
            "policy": self.policy.to_dict() if self.policy else None,
        }


def audit_password(
    password: str,
    policy: Policy = DEFAULT_POLICY,
    mask_style: str = "partial",
) -> AuditResult:
    """Audit one password: entropy + patterns + policy verdict."""
    bits = entropy_bits(password)
    patterns = find_patterns(password)
    result = evaluate(password, policy, entropy=bits, patterns=patterns)
    return AuditResult(
        masked=mask_password(password, mask_style),
        length=len(password),
        charset_size=charset_size(password),
        entropy_bits=bits,
        shannon_per_char=shannon_entropy_per_char(password),
        shannon_total=shannon_entropy_total(password),
        strength=strength_label(bits),
        patterns=patterns,
        policy=result,
    )


def parse_batch_lines(text: str) -> list[str]:
    """Parse batch input: one password per line.

    Blank lines and lines starting with ``#`` are skipped. Leading and
    trailing spaces are preserved (they may be part of a password);
    only the line ending is stripped.
    """
    passwords: list[str] = []
    for line in text.splitlines():
        if line == "" or line.startswith("#"):
            continue
        passwords.append(line)
    return passwords


def audit_batch(
    passwords: list[str],
    policy: Policy = DEFAULT_POLICY,
    mask_style: str = "partial",
) -> list[AuditResult]:
    return [audit_password(pw, policy, mask_style) for pw in passwords]


def audit_file(
    path: str | Path,
    policy: Policy = DEFAULT_POLICY,
    mask_style: str = "partial",
) -> list[AuditResult]:
    text = Path(path).read_text(encoding="utf-8")
    return audit_batch(parse_batch_lines(text), policy, mask_style)


def results_to_json(results: list[AuditResult], *, indent: int = 2) -> str:
    payload = {
        "count": len(results),
        "passed": sum(1 for r in results if r.policy and r.policy.passed),
        "failed": sum(1 for r in results if r.policy and not r.policy.passed),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=indent)


_CSV_FIELDS = [
    "index", "masked", "length", "charset_size", "entropy_bits",
    "shannon_per_char", "strength", "passed", "score", "patterns",
]


def results_to_csv(results: list[AuditResult]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for i, r in enumerate(results, start=1):
        writer.writerow(
            {
                "index": i,
                "masked": r.masked,
                "length": r.length,
                "charset_size": r.charset_size,
                "entropy_bits": f"{r.entropy_bits:.2f}",
                "shannon_per_char": f"{r.shannon_per_char:.4f}",
                "strength": r.strength,
                "passed": bool(r.policy and r.policy.passed),
                "score": r.policy.score if r.policy else "",
                "patterns": ";".join(p.kind for p in r.patterns),
            }
        )
    return buffer.getvalue()


def format_text_report(results: list[AuditResult]) -> str:
    """Human-readable batch report (masked passwords only)."""
    lines: list[str] = []
    passed = sum(1 for r in results if r.policy and r.policy.passed)
    lines.append(f"audited {len(results)} password(s): {passed} passed, "
                 f"{len(results) - passed} failed")
    for i, r in enumerate(results, start=1):
        verdict = "PASS" if (r.policy and r.policy.passed) else "FAIL"
        score = r.policy.score if r.policy else 0
        lines.append(
            f"{i:>3}. {r.masked:<24} len={r.length:<3} "
            f"entropy={r.entropy_bits:6.1f} bits  {r.strength:<12} "
            f"{verdict} (score {score})"
        )
        if r.policy:
            for failure in r.policy.failures:
                lines.append(f"     - {failure}")
    return "\n".join(lines)

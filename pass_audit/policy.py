"""Configurable password policy: length, character classes, entropy, patterns.

A :class:`Policy` describes what an acceptable password looks like.
:func:`evaluate` checks one password against it and returns a
:class:`PolicyResult` with a pass/fail verdict, a 0-100 score, and a
human-readable list of failures.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .entropy import character_classes, entropy_bits
from .patterns import PatternFinding, find_patterns


@dataclass(frozen=True)
class Policy:
    """Password policy knobs. Defaults follow common modern guidance
    (NIST SP 800-63B favours length; 12+ chars with mixed classes and
    >= 60 bits of charset entropy is a solid baseline)."""

    min_length: int = 12
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    min_entropy_bits: float = 60.0
    forbid_patterns: bool = True

    def to_dict(self) -> dict:
        return {
            "min_length": self.min_length,
            "require_lower": self.require_lower,
            "require_upper": self.require_upper,
            "require_digit": self.require_digit,
            "require_symbol": self.require_symbol,
            "min_entropy_bits": self.min_entropy_bits,
            "forbid_patterns": self.forbid_patterns,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


DEFAULT_POLICY = Policy()


@dataclass
class PolicyResult:
    passed: bool
    score: int  # 0-100
    failures: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "score": self.score,
            "failures": list(self.failures),
            "checks": dict(self.checks),
        }


# Score weights: length and entropy dominate; each required class and
# the no-pattern rule contribute the rest. Total = 100.
_WEIGHTS = {
    "length": 25,
    "entropy": 25,
    "lower": 10,
    "upper": 10,
    "digit": 10,
    "symbol": 10,
    "patterns": 10,
}


def evaluate(
    password: str,
    policy: Policy = DEFAULT_POLICY,
    *,
    entropy: float | None = None,
    patterns: list[PatternFinding] | None = None,
) -> PolicyResult:
    """Evaluate ``password`` against ``policy``.

    ``entropy`` / ``patterns`` may be passed in precomputed (the audit
    module does this to avoid double work); otherwise they are computed
    here. Score is the weighted fraction of satisfied checks (checks
    for classes the policy does not require always count as satisfied).
    """
    if entropy is None:
        entropy = entropy_bits(password)
    if patterns is None:
        patterns = find_patterns(password)
    classes = character_classes(password)

    checks: dict[str, bool] = {}
    failures: list[str] = []

    checks["length"] = len(password) >= policy.min_length
    if not checks["length"]:
        failures.append(
            f"too short: {len(password)} chars (minimum {policy.min_length})"
        )

    checks["entropy"] = entropy >= policy.min_entropy_bits
    if not checks["entropy"]:
        failures.append(
            f"entropy too low: {entropy:.1f} bits (minimum {policy.min_entropy_bits:.1f})"
        )

    class_requirements = (
        ("lower", policy.require_lower, "lowercase letter"),
        ("upper", policy.require_upper, "uppercase letter"),
        ("digit", policy.require_digit, "digit"),
        ("symbol", policy.require_symbol, "symbol"),
    )
    for name, required, label in class_requirements:
        ok = (not required) or classes[name]
        checks[name] = ok
        if not ok:
            failures.append(f"missing required character class: {label}")

    checks["patterns"] = (not policy.forbid_patterns) or not patterns
    if not checks["patterns"]:
        kinds = ", ".join(sorted({p.kind for p in patterns}))
        failures.append(f"predictable pattern(s) found: {kinds}")

    score = sum(_WEIGHTS[name] for name, ok in checks.items() if ok)
    return PolicyResult(
        passed=all(checks.values()),
        score=score,
        failures=failures,
        checks=checks,
    )

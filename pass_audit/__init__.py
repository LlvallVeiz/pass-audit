"""pass-audit — local password-strength auditor (stdlib only)."""

from .entropy import charset_size, entropy_bits, shannon_entropy_per_char
from .audit import AuditResult, audit_password, audit_batch, mask_password
from .policy import Policy, PolicyResult

__all__ = [
    "charset_size",
    "entropy_bits",
    "shannon_entropy_per_char",
    "AuditResult",
    "audit_password",
    "audit_batch",
    "mask_password",
    "Policy",
    "PolicyResult",
]

__version__ = "1.0.0"

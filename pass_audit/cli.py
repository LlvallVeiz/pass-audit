"""Command-line interface: ``check``, ``batch``, and ``policy`` subcommands.

Everything runs locally; passwords are never transmitted anywhere.
Exit codes: 0 = all checked passwords pass the policy, 1 = at least
one failure (or a usage/file error).
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .audit import (
    audit_file,
    audit_password,
    format_text_report,
    results_to_csv,
    results_to_json,
)
from .policy import DEFAULT_POLICY, Policy


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--min-length", type=int, default=DEFAULT_POLICY.min_length,
                        help=f"minimum length (default {DEFAULT_POLICY.min_length})")
    parser.add_argument("--min-entropy", type=float, default=DEFAULT_POLICY.min_entropy_bits,
                        help=f"minimum entropy bits (default {DEFAULT_POLICY.min_entropy_bits})")
    parser.add_argument("--no-require-lower", action="store_true", help="don't require a lowercase letter")
    parser.add_argument("--no-require-upper", action="store_true", help="don't require an uppercase letter")
    parser.add_argument("--no-require-digit", action="store_true", help="don't require a digit")
    parser.add_argument("--no-require-symbol", action="store_true", help="don't require a symbol")
    parser.add_argument("--allow-patterns", action="store_true",
                        help="don't fail passwords containing predictable patterns")
    parser.add_argument("--policy-file", type=Path, default=None,
                        help="JSON file with policy fields (overrides the flags above)")


def _policy_from_args(args: argparse.Namespace) -> Policy:
    if getattr(args, "policy_file", None):
        data = json.loads(Path(args.policy_file).read_text(encoding="utf-8"))
        return Policy.from_dict(data)
    return Policy(
        min_length=args.min_length,
        require_lower=not args.no_require_lower,
        require_upper=not args.no_require_upper,
        require_digit=not args.no_require_digit,
        require_symbol=not args.no_require_symbol,
        min_entropy_bits=args.min_entropy,
        forbid_patterns=not args.allow_patterns,
    )


def _format_single(result, *, as_json: bool) -> str:
    if as_json:
        return json.dumps(result.to_dict(), indent=2)
    policy = result.policy
    verdict = "PASS" if (policy and policy.passed) else "FAIL"
    lines = [
        f"password (masked): {result.masked}",
        f"length:            {result.length}",
        f"charset size (N):  {result.charset_size}",
        f"entropy H=L*log2(N): {result.entropy_bits:.2f} bits ({result.strength})",
        f"shannon per char:  {result.shannon_per_char:.4f} bits "
        f"(total {result.shannon_total:.2f})",
        f"policy:            {verdict} (score {policy.score if policy else 0}/100)",
    ]
    if result.patterns:
        lines.append("patterns found:")
        lines.extend(f"  - {p.kind}: {p.detail}" for p in result.patterns)
    else:
        lines.append("patterns found:    none")
    if policy and policy.failures:
        lines.append("failures:")
        lines.extend(f"  - {failure}" for failure in policy.failures)
    return "\n".join(lines)


def cmd_check(args: argparse.Namespace) -> int:
    password = args.password
    if password is None:
        password = getpass.getpass("Password (input hidden): ")
    policy = _policy_from_args(args)
    result = audit_password(password, policy, mask_style=args.mask)
    print(_format_single(result, as_json=args.json))
    return 0 if (result.policy and result.policy.passed) else 1


def cmd_batch(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    try:
        results = audit_file(args.file, policy, mask_style=args.mask)
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        output = results_to_json(results)
    elif args.format == "csv":
        output = results_to_csv(results)
    else:
        output = format_text_report(results)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.format} report for {len(results)} password(s) to {args.output}")
    else:
        print(output)
    failed = sum(1 for r in results if not (r.policy and r.policy.passed))
    return 0 if failed == 0 else 1


def cmd_policy(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    if args.json:
        print(json.dumps(policy.to_dict(), indent=2))
    else:
        print("active password policy:")
        for key, value in policy.to_dict().items():
            print(f"  {key}: {value}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pass-audit",
        description="Audit password strength locally (entropy, patterns, policy).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="audit a single password")
    p_check.add_argument("password", nargs="?", default=None,
                         help="password to check (omit to type it hidden)")
    p_check.add_argument("--json", action="store_true", help="output JSON")
    p_check.add_argument("--mask", choices=("partial", "full"), default="partial")
    _add_policy_args(p_check)
    p_check.set_defaults(func=cmd_check)

    p_batch = sub.add_parser("batch", help="audit passwords from a file (one per line)")
    p_batch.add_argument("file", type=Path, help="input file, one password per line")
    p_batch.add_argument("--format", choices=("text", "json", "csv"), default="text")
    p_batch.add_argument("--output", type=Path, default=None, help="write report to this file")
    p_batch.add_argument("--mask", choices=("partial", "full"), default="partial")
    _add_policy_args(p_batch)
    p_batch.set_defaults(func=cmd_batch)

    p_policy = sub.add_parser("policy", help="show the active policy")
    p_policy.add_argument("--json", action="store_true", help="output JSON")
    _add_policy_args(p_policy)
    p_policy.set_defaults(func=cmd_policy)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

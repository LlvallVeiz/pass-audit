# pass-audit

A local password-strength auditor CLI written in pure Python 3.12
(standard library only — no third-party dependencies). It estimates
password entropy, detects predictable patterns, scores passwords
against a configurable policy, and can audit a whole file of passwords
with masked reports.

## Security note

Everything runs **locally on your machine**. pass-audit never
transmits passwords anywhere: no network calls, no telemetry, no
logging of plaintext. Batch reports (text / JSON / CSV) always mask
passwords (see [Masking](#masking)), so a report file never contains a
usable password. For the `check` command you can omit the password
argument and type it at a hidden prompt instead of putting it in your
shell history.

## Quick start

Requires Python 3.12+. No installation step is needed; run it as a
module from the repository root:

```sh
# audit one password (hidden prompt if you omit the argument)
python3 -m pass_audit check
python3 -m pass_audit check 'X9!mQ2#vL8pZ4&'

# audit a file (one password per line)
python3 -m pass_audit batch passwords.txt
python3 -m pass_audit batch passwords.txt --format json --output report.json
python3 -m pass_audit batch passwords.txt --format csv

# show the active policy
python3 -m pass_audit policy
```

Exit code is `0` when every checked password passes the policy and
`1` otherwise, so it composes well in scripts.

## How it works

### Entropy

Two estimates are computed (`pass_audit/entropy.py`):

1. **Charset entropy** — `H = L * log2(N)`, where `L` is the password
   length and `N` is the charset size estimated from the character
   classes present:

   | class      | size |
   |------------|------|
   | lowercase  | 26   |
   | uppercase  | 26   |
   | digits     | 10   |
   | symbols (`string.punctuation`) | 32 |
   | space      | 1    |
   | non-ASCII  | 64   |

   A password using every ASCII class has N = 95 (printable ASCII).
   Example: `aA1!` → L = 4, N = 94 → H ≈ 26.2 bits.

2. **Per-character Shannon entropy** — `H_c = -sum(p_i * log2(p_i))`
   over the observed character frequencies. It is 0 for a password of
   one repeated character and `log2(k)` for `k` equally frequent
   distinct characters. The total is `H_c * L`.

Strength labels from charset entropy: `< 28` bits very weak,
`28–35` weak, `36–59` fair, `60–127` strong, `>= 128` very strong.

### Pattern checks (`pass_audit/patterns.py`)

Charset entropy assumes random characters; human passwords aren't.
These checks flag what attackers try first:

- **Dictionary** — bundled list of common passwords/words, matched
  case-insensitively, as substrings, and after leetspeak normalisation
  (`p@ssw0rd` → `password`).
- **Sequences** — ascending/descending runs of 3+ (`abc`, `123`, `cba`).
- **Repeats** — the same character 3+ times (`aaa`, `111`) and
  repeated blocks (`abcabc`).
- **Keyboard walks** — contiguous QWERTY-row runs of 3+ keys
  (`qwerty`, `asdf`, `zxcv`), forwards or backwards.

### Policy (`pass_audit/policy.py`)

Default policy (every knob is configurable via CLI flags or a JSON
`--policy-file`):

```json
{
  "min_length": 12,
  "require_lower": true,
  "require_upper": true,
  "require_digit": true,
  "require_symbol": true,
  "min_entropy_bits": 60.0,
  "forbid_patterns": true
}
```

Each password gets a pass/fail verdict, a 0–100 score (length 25,
entropy 25, each required class 10, no-patterns 10), and a list of
human-readable failures. Override from the CLI, e.g.:

```sh
python3 -m pass_audit check 'somepass' --min-length 8 --min-entropy 40 --no-require-symbol
python3 -m pass_audit batch passwords.txt --policy-file my-policy.json
```

### Masking

Batch reports never contain a full password:

- `--mask partial` (default): only the first and last character stay
  visible — `hunter2` → `h*****2`. Passwords of length ≤ 2 are masked
  completely (`**`).
- `--mask full`: every character replaced — `hunter2` → `*******`.

## Batch input format

One password per line. Blank lines and lines starting with `#` are
skipped. Leading/trailing spaces are preserved (they may be part of a
password).

## Project layout

```
pass_audit/
  __init__.py    public API
  __main__.py    `python -m pass_audit` entry point
  entropy.py     charset size, H = L*log2(N), Shannon entropy
  patterns.py    dictionary / sequence / repeat / keyboard-walk checks
  policy.py      configurable Policy + scoring
  audit.py       single + batch audits, masking, JSON/CSV/text reports
  cli.py         argparse CLI: check / batch / policy
tests/           unittest suite (entropy, patterns, policy, audit, cli)
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

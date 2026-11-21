"""Pattern detection: dictionary words, sequences, repeats, keyboard walks.

Charset entropy assumes random characters; human-chosen passwords are
not random. These checks flag the predictable structures attackers try
first. Every check returns :class:`PatternFinding` objects; an empty
list means no known pattern was found.
"""

from __future__ import annotations

from dataclasses import dataclass

# Small bundled list of very common passwords / words. Deliberately
# short (this is an auditor demo, not a breach corpus): it catches the
# worst offenders. Real deployments should plug in a large breach list.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "passwd", "passw0rd", "letmein", "welcome", "admin",
        "administrator", "root", "login", "secret", "master", "dragon",
        "monkey", "football", "baseball", "sunshine", "iloveyou", "princess",
        "superman", "batman", "shadow", "michael", "jennifer", "computer",
        "internet", "samsung", "google", "yahoo", "hello", "freedom",
        "whatever", "qwerty", "qwerty123", "123456", "12345678", "123456789",
        "12345", "123123", "111111", "000000", "654321", "abc123", "1q2w3e",
        "qazwsx", "zxcvbnm", "asdfgh", "trustno1", "starwars", "pokemon",
        "naruto", "lol123", "password1", "password123", "changeme",
        "default", "guest", "test", "demo", "pass", "word", "love", "god",
        "sex", "1234", "123", "killer", "hunter", "charlie", "andrew",
        "joshua", "daniel", "thomas", "george", "jordan", "tigger",
        "robert", "soccer", "hockey", "ranger", "buster", "jessica",
        "pepper", "1234567", "zxcvbn", "killer", "sandra", "purple",
        "orange", "banana", "apple", "summer", "winter", "spring", "autumn",
        "jakarta", "indonesia", "sayang", "cinta", "bismillah", "admin123",
    }
)

# Common leetspeak substitutions, used to catch e.g. "p@ssw0rd".
_LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
                           "$": "s", "5": "s", "3": "e", "7": "t", "+": "t"})

# QWERTY keyboard rows (also checked reversed).
_KEYBOARD_ROWS = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

MIN_DICTIONARY_LEN = 4   # shorter dictionary hits are too noisy
MIN_SEQUENCE_LEN = 3     # e.g. "abc", "123", "cba"
MIN_REPEAT_LEN = 3       # e.g. "aaa", "111"
MIN_KEYBOARD_LEN = 3     # e.g. "qwe", "asd" (walks of 3+ keys)


@dataclass(frozen=True)
class PatternFinding:
    kind: str    # "dictionary" | "sequence" | "repeat" | "keyboard_walk" | "repeated_pattern"
    detail: str  # human-readable explanation (never contains password text)


def _dictionary_findings(password: str) -> list[PatternFinding]:
    lowered = password.lower()
    normalized = lowered.translate(_LEET_MAP)
    findings: list[PatternFinding] = []
    for candidate in {lowered, normalized}:
        if candidate in COMMON_PASSWORDS:
            findings.append(PatternFinding("dictionary", "is a common password"))
            return findings
    for word in COMMON_PASSWORDS:
        if len(word) < MIN_DICTIONARY_LEN:
            continue
        if word in lowered or word in normalized:
            findings.append(
                PatternFinding("dictionary", "contains a common word")
            )
            break  # one dictionary finding is enough
    return findings


def _sequence_findings(password: str) -> list[PatternFinding]:
    """Ascending/descending runs of >= MIN_SEQUENCE_LEN (abc, 321, ...)."""
    findings: list[PatternFinding] = []
    if len(password) < MIN_SEQUENCE_LEN:
        return findings
    run_start = 0
    direction = 0  # +1 ascending, -1 descending
    for i in range(1, len(password) + 1):
        step = 0
        if i < len(password):
            diff = ord(password[i].lower()) - ord(password[i - 1].lower())
            if diff == 1:
                step = 1
            elif diff == -1:
                step = -1
        if step != 0 and step == direction:
            continue
        # Run [run_start, i) just ended.
        if direction != 0 and (i - run_start) >= MIN_SEQUENCE_LEN:
            kind_word = "ascending" if direction == 1 else "descending"
            findings.append(
                PatternFinding(
                    "sequence",
                    f"{kind_word} sequence of length {i - run_start} at position {run_start}",
                )
            )
        run_start = i - 1 if step != 0 else i
        direction = step
    return findings


def _repeat_findings(password: str) -> list[PatternFinding]:
    """Same character repeated >= MIN_REPEAT_LEN times, plus repeated blocks."""
    findings: list[PatternFinding] = []
    if not password:
        return findings
    run_start = 0
    for i in range(1, len(password) + 1):
        if i < len(password) and password[i] == password[run_start]:
            continue
        run_len = i - run_start
        if run_len >= MIN_REPEAT_LEN:
            findings.append(
                PatternFinding(
                    "repeat",
                    f"same character repeated {run_len} times at position {run_start}",
                )
            )
        run_start = i
    # Repeated block, e.g. "abcabc" or "1212" (block length >= 2, twice).
    n = len(password)
    for block_len in range(2, n // 2 + 1):
        block = password[:block_len]
        if block * (n // block_len) == password[: block_len * (n // block_len)] and n % block_len == 0:
            findings.append(
                PatternFinding("repeated_pattern", f"block of length {block_len} repeated")
            )
            break
    return findings


def _keyboard_findings(password: str) -> list[PatternFinding]:
    """Contiguous walks along a QWERTY row (qwerty, asdf, zxcv, ...)."""
    findings: list[PatternFinding] = []
    lowered = password.lower()
    if len(lowered) < MIN_KEYBOARD_LEN:
        return findings
    rows = list(_KEYBOARD_ROWS) + [row[::-1] for row in _KEYBOARD_ROWS]
    found: set[str] = set()
    for start in range(len(lowered)):
        for end in range(start + MIN_KEYBOARD_LEN, len(lowered) + 1):
            fragment = lowered[start:end]
            if any(fragment in row for row in rows):
                found.add(fragment)
    # Keep only maximal fragments (drop ones contained in a longer hit).
    maximal = [f for f in found if not any(f != other and f in other for other in found)]
    for fragment in sorted(maximal):
        findings.append(
            PatternFinding("keyboard_walk", f"keyboard walk of length {len(fragment)}")
        )
    return findings


def find_patterns(password: str) -> list[PatternFinding]:
    """Run all pattern checks and return every finding."""
    if not password:
        return []
    findings: list[PatternFinding] = []
    findings.extend(_dictionary_findings(password))
    findings.extend(_sequence_findings(password))
    findings.extend(_repeat_findings(password))
    findings.extend(_keyboard_findings(password))
    return findings

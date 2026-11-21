"""Entropy estimation for passwords.

Two complementary estimates are provided:

1. **Charset (brute-force) entropy**

       H = L * log2(N)

   where ``L`` is the password length and ``N`` is the size of the
   character set the password draws from (estimated from the character
   classes present). This is the classic upper-bound estimate used by
   password-strength meters: it assumes every character is chosen
   uniformly at random from the charset, so real-world strength is
   usually lower — which is why pattern checks live in
   :mod:`pass_audit.patterns`.

2. **Per-character Shannon entropy**

       H_c = -sum(p_i * log2(p_i))

   where ``p_i`` is the observed frequency of each distinct character
   in the password itself. ``H_c`` is 0 for a password made of a single
   repeated character and grows with character diversity. The total
   Shannon estimate is ``H_c * L``.

Charset sizes (number of possible characters per class):

===========  ====
lowercase     26  (a-z)
uppercase     26  (A-Z)
digits        10  (0-9)
symbols       32  (``string.punctuation``)
space          1
non-ASCII     64  (conservative bucket for accented / CJK / emoji input)
===========  ====

A password using all ASCII classes therefore has N = 95, the size of
printable ASCII.
"""

from __future__ import annotations

import math
import string
from collections import Counter

LOWER_SIZE = 26
UPPER_SIZE = 26
DIGIT_SIZE = 10
SYMBOL_SIZE = len(string.punctuation)  # 32
SPACE_SIZE = 1
NON_ASCII_SIZE = 64

_SYMBOLS = set(string.punctuation)


def character_classes(password: str) -> dict[str, bool]:
    """Return which character classes appear in ``password``."""
    classes = {
        "lower": False,
        "upper": False,
        "digit": False,
        "symbol": False,
        "space": False,
        "non_ascii": False,
    }
    for ch in password:
        if "a" <= ch <= "z":
            classes["lower"] = True
        elif "A" <= ch <= "Z":
            classes["upper"] = True
        elif "0" <= ch <= "9":
            classes["digit"] = True
        elif ch in _SYMBOLS:
            classes["symbol"] = True
        elif ch == " ":
            classes["space"] = True
        elif ord(ch) > 127:
            classes["non_ascii"] = True
        else:
            # Other ASCII control/whitespace characters: count as symbols.
            classes["symbol"] = True
    return classes


def charset_size(password: str) -> int:
    """Estimate N, the charset size, from the classes present.

    Empty password -> 0. A password using one class returns that
    class's size (e.g. ``"abc"`` -> 26, ``"123"`` -> 10).
    """
    if not password:
        return 0
    classes = character_classes(password)
    size = 0
    if classes["lower"]:
        size += LOWER_SIZE
    if classes["upper"]:
        size += UPPER_SIZE
    if classes["digit"]:
        size += DIGIT_SIZE
    if classes["symbol"]:
        size += SYMBOL_SIZE
    if classes["space"]:
        size += SPACE_SIZE
    if classes["non_ascii"]:
        size += NON_ASCII_SIZE
    return size


def entropy_bits(password: str) -> float:
    """Charset entropy ``H = L * log2(N)`` in bits.

    Returns 0.0 for an empty password or a degenerate charset (N <= 1).
    """
    if not password:
        return 0.0
    n = charset_size(password)
    if n <= 1:
        return 0.0
    return len(password) * math.log2(n)


def shannon_entropy_per_char(password: str) -> float:
    """Per-character Shannon entropy ``-sum(p_i * log2(p_i))`` in bits.

    0.0 for empty input or a single distinct character. Maximum is
    ``log2(k)`` for ``k`` equally frequent distinct characters.
    """
    if not password:
        return 0.0
    counts = Counter(password)
    length = len(password)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def shannon_entropy_total(password: str) -> float:
    """Total Shannon estimate: per-character entropy times length."""
    return shannon_entropy_per_char(password) * len(password)

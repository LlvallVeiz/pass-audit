import math
import unittest

from pass_audit.entropy import (
    charset_size,
    character_classes,
    entropy_bits,
    shannon_entropy_per_char,
    shannon_entropy_total,
)


class TestCharsetSize(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(charset_size(""), 0)

    def test_lowercase_only(self):
        self.assertEqual(charset_size("abcxyz"), 26)

    def test_uppercase_only(self):
        self.assertEqual(charset_size("ABCXYZ"), 26)

    def test_digits_only(self):
        self.assertEqual(charset_size("0123456789"), 10)

    def test_symbols_only(self):
        self.assertEqual(charset_size("!@#$"), 32)

    def test_mixed_classes(self):
        # lower 26 + upper 26 + digit 10 + symbol 32 = 94
        self.assertEqual(charset_size("aA1!"), 94)

    def test_all_printable_ascii(self):
        # 94 + space 1 = 95
        self.assertEqual(charset_size("aA1! "), 95)

    def test_character_classes(self):
        classes = character_classes("aA1!")
        self.assertTrue(classes["lower"])
        self.assertTrue(classes["upper"])
        self.assertTrue(classes["digit"])
        self.assertTrue(classes["symbol"])
        self.assertFalse(classes["space"])


class TestEntropyBits(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(entropy_bits(""), 0.0)

    def test_single_char(self):
        # L=1, N=26 -> log2(26)
        self.assertAlmostEqual(entropy_bits("a"), math.log2(26), places=10)

    def test_all_same_char(self):
        # Charset formula does not penalise repetition: 8 * log2(26).
        self.assertAlmostEqual(entropy_bits("aaaaaaaa"), 8 * math.log2(26), places=10)

    def test_known_case_digits(self):
        # 4-digit PIN: 4 * log2(10)
        self.assertAlmostEqual(entropy_bits("1234"), 4 * math.log2(10), places=10)

    def test_known_case_mixed(self):
        # "aA1!": L=4, N=94
        self.assertAlmostEqual(entropy_bits("aA1!"), 4 * math.log2(94), places=10)

    def test_longer_password_more_entropy(self):
        self.assertGreater(entropy_bits("abcdefghij"), entropy_bits("abc"))


class TestShannonEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy_per_char(""), 0.0)

    def test_single_char_is_zero(self):
        self.assertEqual(shannon_entropy_per_char("a"), 0.0)

    def test_all_same_char_is_zero(self):
        self.assertEqual(shannon_entropy_per_char("aaaaaaaa"), 0.0)

    def test_two_equal_chars_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy_per_char("abab"), 1.0, places=10)

    def test_four_equal_chars_is_two_bits(self):
        self.assertAlmostEqual(shannon_entropy_per_char("abcd"), 2.0, places=10)

    def test_total_is_per_char_times_length(self):
        self.assertAlmostEqual(
            shannon_entropy_total("abcd"), shannon_entropy_per_char("abcd") * 4, places=10
        )


if __name__ == "__main__":
    unittest.main()

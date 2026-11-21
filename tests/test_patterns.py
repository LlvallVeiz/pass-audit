import unittest

from pass_audit.patterns import find_patterns


def kinds(password):
    return {f.kind for f in find_patterns(password)}


class TestDictionary(unittest.TestCase):
    def test_exact_common_password(self):
        self.assertIn("dictionary", kinds("password"))

    def test_common_password_case_insensitive(self):
        self.assertIn("dictionary", kinds("PASSWORD"))

    def test_contains_common_word(self):
        self.assertIn("dictionary", kinds("myDragon99!"))

    def test_leetspeak_variant(self):
        self.assertIn("dictionary", kinds("p@ssw0rd"))


class TestSequences(unittest.TestCase):
    def test_ascending_letters(self):
        self.assertIn("sequence", kinds("abc"))

    def test_ascending_digits(self):
        self.assertIn("sequence", kinds("123"))

    def test_descending(self):
        self.assertIn("sequence", kinds("cba"))

    def test_embedded_sequence(self):
        self.assertIn("sequence", kinds("Xy9abcQ!"))


class TestRepeats(unittest.TestCase):
    def test_repeated_letter(self):
        self.assertIn("repeat", kinds("aaa"))

    def test_repeated_digit(self):
        self.assertIn("repeat", kinds("111"))

    def test_repeated_block(self):
        self.assertIn("repeated_pattern", kinds("abcabc"))


class TestKeyboardWalks(unittest.TestCase):
    def test_qwerty(self):
        self.assertIn("keyboard_walk", kinds("qwerty"))

    def test_asdf(self):
        self.assertIn("keyboard_walk", kinds("asdf"))

    def test_embedded_walk(self):
        self.assertIn("keyboard_walk", kinds("9zxcvb2!"))


class TestCleanPassword(unittest.TestCase):
    def test_no_patterns(self):
        self.assertEqual(find_patterns("X9!mQ2#vL8pZ"), [])

    def test_empty_password(self):
        self.assertEqual(find_patterns(""), [])


if __name__ == "__main__":
    unittest.main()

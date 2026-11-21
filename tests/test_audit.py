import json
import unittest

from pass_audit.audit import (
    audit_batch,
    audit_password,
    format_text_report,
    mask_password,
    parse_batch_lines,
    results_to_csv,
    results_to_json,
    strength_label,
)

STRONG = "X9!mQ2#vL8pZ4&"
WEAK = "password"


class TestMasking(unittest.TestCase):
    def test_partial_mask(self):
        self.assertEqual(mask_password("hunter2"), "h*****2")

    def test_partial_mask_never_reveals_full(self):
        for pw in ("hunter2", "ab", "a", "longpassword123"):
            masked = mask_password(pw, "partial")
            self.assertNotEqual(masked, pw)
            if len(pw) > 2:
                self.assertNotIn(pw[1:-1], masked)

    def test_short_passwords_fully_masked(self):
        self.assertEqual(mask_password("ab"), "**")
        self.assertEqual(mask_password("a"), "*")

    def test_full_mask(self):
        self.assertEqual(mask_password("hunter2", "full"), "*******")

    def test_empty_mask(self):
        self.assertEqual(mask_password(""), "")

    def test_bad_style_raises(self):
        with self.assertRaises(ValueError):
            mask_password("x", "bogus")


class TestStrengthLabel(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(strength_label(10), "very weak")
        self.assertEqual(strength_label(30), "weak")
        self.assertEqual(strength_label(45), "fair")
        self.assertEqual(strength_label(80), "strong")
        self.assertEqual(strength_label(200), "very strong")


class TestBatchParsing(unittest.TestCase):
    def test_skips_blanks_and_comments(self):
        text = "# header\nfoo\n\nbar baz\n# trailing\n"
        self.assertEqual(parse_batch_lines(text), ["foo", "bar baz"])

    def test_preserves_spaces(self):
        self.assertEqual(parse_batch_lines(" spaced \n"), [" spaced "])


class TestAuditReports(unittest.TestCase):
    def setUp(self):
        self.results = audit_batch([STRONG, WEAK])

    def test_audit_single_fields(self):
        result = audit_password(STRONG)
        self.assertEqual(result.length, len(STRONG))
        self.assertGreater(result.entropy_bits, 60)
        self.assertTrue(result.policy.passed)

    def test_json_report_is_masked(self):
        payload = results_to_json(self.results)
        self.assertNotIn(STRONG, payload)
        # WEAK is the literal word "password", which legitimately
        # appears in prose ("is a common password"); assert it never
        # appears as a JSON string value and the masked form does.
        self.assertNotIn(f'"{WEAK}"', payload)
        self.assertIn(mask_password(WEAK), payload)
        data = json.loads(payload)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["passed"], 1)
        self.assertEqual(data["failed"], 1)
        self.assertEqual(data["results"][0]["masked"], mask_password(STRONG))

    def test_csv_report_is_masked(self):
        payload = results_to_csv(self.results)
        self.assertNotIn(STRONG, payload)
        self.assertNotIn(WEAK, payload)
        lines = payload.strip().splitlines()
        self.assertEqual(len(lines), 3)  # header + 2 rows
        self.assertTrue(lines[0].startswith("index,masked"))

    def test_text_report_is_masked(self):
        payload = format_text_report(self.results)
        self.assertNotIn(STRONG, payload)
        # The header legitimately says "password(s)", so check the weak
        # password does not appear as a standalone token and its masked
        # form does.
        self.assertNotIn(f" {WEAK} ", payload)
        self.assertNotIn(f'"{WEAK}"', payload)
        self.assertIn(mask_password(WEAK), payload)
        self.assertIn("1 passed, 1 failed", payload)


if __name__ == "__main__":
    unittest.main()

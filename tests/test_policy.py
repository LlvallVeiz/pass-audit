import unittest

from pass_audit.policy import DEFAULT_POLICY, Policy, evaluate

STRONG = "X9!mQ2#vL8pZ4&"  # 14 chars, all classes, no patterns


class TestPolicyPassFail(unittest.TestCase):
    def test_strong_password_passes_default(self):
        result = evaluate(STRONG, DEFAULT_POLICY)
        self.assertTrue(result.passed, result.failures)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.failures, [])

    def test_short_password_fails(self):
        result = evaluate("aA1!", DEFAULT_POLICY)
        self.assertFalse(result.passed)
        self.assertFalse(result.checks["length"])

    def test_missing_classes_fail(self):
        result = evaluate("abcdefghijkl", DEFAULT_POLICY)  # lower only, 12 chars
        self.assertFalse(result.passed)
        self.assertFalse(result.checks["upper"])
        self.assertFalse(result.checks["digit"])
        self.assertFalse(result.checks["symbol"])

    def test_low_entropy_fails(self):
        policy = Policy(min_length=4, require_lower=False, require_upper=False,
                        require_digit=False, require_symbol=False,
                        min_entropy_bits=60.0, forbid_patterns=False)
        result = evaluate("abcd", policy)
        self.assertFalse(result.passed)
        self.assertFalse(result.checks["entropy"])

    def test_pattern_password_fails(self):
        result = evaluate("Password123!", DEFAULT_POLICY)
        self.assertFalse(result.passed)
        self.assertFalse(result.checks["patterns"])

    def test_relaxed_policy_passes(self):
        policy = Policy(min_length=4, require_lower=True, require_upper=False,
                        require_digit=False, require_symbol=False,
                        min_entropy_bits=10.0, forbid_patterns=False)
        result = evaluate("xkcd", policy)
        self.assertTrue(result.passed, result.failures)

    def test_score_between_0_and_100(self):
        for pw in ("", "a", "password", STRONG):
            result = evaluate(pw, DEFAULT_POLICY)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)

    def test_policy_dict_round_trip(self):
        policy = Policy(min_length=8, min_entropy_bits=40.0)
        clone = Policy.from_dict(policy.to_dict())
        self.assertEqual(clone, policy)


if __name__ == "__main__":
    unittest.main()

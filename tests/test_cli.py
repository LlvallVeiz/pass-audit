import json
import tempfile
import unittest
from pathlib import Path

from pass_audit.cli import main

STRONG = "X9!mQ2#vL8pZ4&"


class TestCli(unittest.TestCase):
    def test_check_strong_exit_zero(self):
        self.assertEqual(main(["check", STRONG]), 0)

    def test_check_weak_exit_one(self):
        self.assertEqual(main(["check", "password"]), 1)

    def test_check_json(self):
        self.assertEqual(main(["check", STRONG, "--json"]), 0)

    def test_policy_command(self):
        self.assertEqual(main(["policy"]), 0)
        self.assertEqual(main(["policy", "--json"]), 0)

    def test_batch_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "pws.txt"
            src.write_text(f"{STRONG}\npassword\n", encoding="utf-8")
            # one weak password -> exit 1
            self.assertEqual(main(["batch", str(src)]), 1)
            self.assertEqual(main(["batch", str(src), "--format", "json"]), 1)
            self.assertEqual(main(["batch", str(src), "--format", "csv"]), 1)

    def test_batch_output_file_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "pws.txt"
            out = Path(tmp) / "report.json"
            src.write_text(f"{STRONG}\n", encoding="utf-8")
            self.assertEqual(
                main(["batch", str(src), "--format", "json", "--output", str(out)]), 0
            )
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["count"], 1)
            self.assertNotIn(STRONG, out.read_text(encoding="utf-8"))

    def test_batch_missing_file(self):
        self.assertEqual(main(["batch", "/nonexistent/pws.txt"]), 1)


if __name__ == "__main__":
    unittest.main()

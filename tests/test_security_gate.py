"""
Tests for the DevSecOps security gate.
Validates threshold logic without needing real scan output.
Author: Sunny Bhardwaj
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from security_gate import evaluate_gate, THRESHOLDS, _parse_bandit


class TestSecurityGate(unittest.TestCase):

    def test_empty_reports_pass(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(evaluate_gate(d))

    def test_critical_finding_fails(self):
        with tempfile.TemporaryDirectory() as d:
            bandit = {"results": [{"issue_severity": "CRITICAL"}]}
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit, f)
            # One CRITICAL exceeds threshold of 0
            self.assertFalse(evaluate_gate(d))

    def test_high_under_threshold_passes(self):
        with tempfile.TemporaryDirectory() as d:
            bandit = {"results": [{"issue_severity": "HIGH"}]}
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit, f)
            # One HIGH is under threshold of 5
            self.assertTrue(evaluate_gate(d))

    def test_high_over_threshold_fails(self):
        with tempfile.TemporaryDirectory() as d:
            bandit = {"results": [{"issue_severity": "HIGH"}] * 6}
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit, f)
            # Six HIGH exceeds threshold of 5
            self.assertFalse(evaluate_gate(d))

    def test_thresholds_defined(self):
        self.assertEqual(THRESHOLDS["CRITICAL"], 0)
        self.assertIn("HIGH", THRESHOLDS)


if __name__ == "__main__":
    unittest.main()

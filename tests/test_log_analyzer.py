"""Unit tests for `starter_log_analyzer.py`.

These tests exercise the log parsing function using a small sample log file
located in `tests/sample_auth.log`. They validate the total event count and
per-IP aggregation.
"""

import unittest
import os
from starter_log_analyzer import parse_auth_log


class TestLogAnalyzer(unittest.TestCase):
    def test_parse_sample(self):
        # Locate the bundled sample log and run the parser against it.
        path = os.path.join(os.path.dirname(__file__), 'sample_auth.log')
        total, counts = parse_auth_log(path)
        self.assertEqual(total, 5)
        # verify expected per-IP tallies from the sample
        self.assertEqual(counts.get('203.0.113.10'), 2)
        self.assertEqual(counts.get('198.51.100.5'), 2)
        self.assertEqual(counts.get('192.0.2.1'), 1)


if __name__ == '__main__':
    unittest.main()

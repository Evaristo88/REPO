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
        # Ensure the sample fixture exists (creates it if missing) then run parser.
        here = os.path.dirname(__file__)
        path = os.path.join(here, 'sample_auth.log')
        if not os.path.exists(path):
            sample = '''Feb  5 00:00:01 host sshd[1000]: Failed password for invalid user test from 203.0.113.10 port 12345 ssh2
Feb  5 00:00:02 host sshd[1001]: Failed password for root from 203.0.113.10 port 12346 ssh2
Feb  5 00:00:03 host sshd[1002]: Failed password for invalid user nobody from 198.51.100.5 port 2222 ssh2
Feb  5 00:00:04 host sshd[1003]: Failed password for root from 198.51.100.5 port 2223 ssh2
Feb  5 00:00:05 host sshd[1004]: Invalid user admin from 192.0.2.1 port 3333 ssh2
'''
            with open(path, 'w') as fh:
                fh.write(sample)

        total, counts = parse_auth_log(path)
        self.assertEqual(total, 5)
        # verify expected per-IP tallies from the sample
        self.assertEqual(counts.get('203.0.113.10'), 2)
        self.assertEqual(counts.get('198.51.100.5'), 2)
        self.assertEqual(counts.get('192.0.2.1'), 1)


if __name__ == '__main__':
    unittest.main()

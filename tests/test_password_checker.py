"""Unit tests for `starter_password_checker.py`.

These tests call `analyze()` with a representative password to ensure the
character-class detection and entropy estimation behave as expected.
"""

import unittest
from starter_password_checker import analyze


class TestPasswordChecker(unittest.TestCase):
    def test_basic(self):
        r = analyze('Password123!')
        self.assertTrue(r['checks']['has_upper'])
        self.assertTrue(r['checks']['has_lower'])
        self.assertTrue(r['checks']['has_digit'])
        self.assertTrue(r['checks']['has_symbol'])
        self.assertGreater(r['entropy'], 0)


if __name__ == '__main__':
    unittest.main()

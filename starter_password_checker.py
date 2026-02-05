#!/usr/bin/env python3
"""starter_password_checker.py

Simple interactive password checker used for lab exercises.

This script provides a small, local check of password characteristics and a
very rough entropy estimate. It is educational and should not be used as a
sole metric for password acceptance in production systems.
"""

import getpass
import math
import re


def estimate_entropy(password: str) -> float:
	"""Estimate entropy (bits) based on character class pool size.

	This is a simplified estimator: it determines which classes are present
	(lower, upper, digits, symbols), estimates a pool size and multiplies by
	the password length to produce an approximate bits-of-entropy metric.
	"""
	pool = 0
	if re.search(r'[a-z]', password):
		pool += 26
	if re.search(r'[A-Z]', password):
		pool += 26
	if re.search(r'\d', password):
		pool += 10
	if re.search(r'[^A-Za-z0-9]', password):
		pool += 32
	if pool == 0:
		return 0.0
	return len(password) * math.log2(pool)


def analyze(password: str) -> dict:
	"""Analyze password characteristics and compute a simple score.

	Returns a dict with length, checks (which classes are present), estimated
	entropy, and a 0-4 score based on basic heuristics.
	"""
	length = len(password)
	checks = {
		'length': length,
		'has_lower': bool(re.search(r'[a-z]', password)),
		'has_upper': bool(re.search(r'[A-Z]', password)),
		'has_digit': bool(re.search(r'\d', password)),
		'has_symbol': bool(re.search(r'[^A-Za-z0-9]', password)),
	}
	entropy = estimate_entropy(password)
	score = 0
	score += 1 if checks['length'] >= 12 else 0
	score += 1 if checks['has_lower'] and checks['has_upper'] else 0
	score += 1 if checks['has_digit'] else 0
	score += 1 if checks['has_symbol'] else 0
	return {'length': length, 'checks': checks, 'entropy': entropy, 'score': score}


def print_report(result: dict) -> None:
	"""Print a human-readable report and actionable suggestions."""
	print(f"Password length: {result['length']}")
	print(f"Estimated entropy: {result['entropy']:.1f} bits")
	print("Character classes:")
	for k, v in result['checks'].items():
		print(f"  {k}: {v}")
	print(f"Simple score (0-4): {result['score']}" )
	suggestions = []
	if result['length'] < 12:
		suggestions.append('Use at least 12 characters')
	if not result['checks']['has_upper'] or not result['checks']['has_lower']:
		suggestions.append('Mix upper and lower case letters')
	if not result['checks']['has_digit']:
		suggestions.append('Include digits')
	if not result['checks']['has_symbol']:
		suggestions.append('Include symbols or punctuation')
	if result['entropy'] < 60:
		suggestions.append('Consider a longer passphrase or use a password manager')
	if suggestions:
		print('\nSuggestions:')
		for s in suggestions:
			print(' -', s)
	else:
		print('\nPassword meets basic strength heuristics.')


def main():
	"""Prompt for a password (masked) and display the analysis report."""
	pwd = getpass.getpass('Enter password: ')
	res = analyze(pwd)
	print_report(res)


if __name__ == '__main__':
	main()


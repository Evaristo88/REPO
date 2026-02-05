#!/usr/bin/env python3
"""
starter_log_analyzer.py

Simple log analyzer for SSH auth failures.

Features:
- Auto-detects auth log files and supports rotated / gzipped logs.
- Counts failed SSH authentication events per source IP and writes a JSON
	summary report.
- Follow mode (`--follow`) streams new matching events in real time and can
	optionally append offending IPs to a blocklist and attempt to auto-block.

Design notes:
- The implementation is intentionally lightweight and aims to illustrate
	parsing and simple alerting; for production use you should harden parsing,
	handle log timestamp parsing, and integrate with established tooling.
"""

import argparse
import collections
import datetime
import gzip
import glob
import json
import os
import re
import sys
import time
import shutil
import subprocess


def detect_auth_log():
	# Return first existing auth log file; prefer current file but allow rotated patterns
	candidates = ["/var/log/auth.log", "/var/log/secure"]
	for c in candidates:
		if os.path.isfile(c):
			return c
	# fallback: check for rotated variants
	for pattern in ["/var/log/auth.log*", "/var/log/secure*"]:
		matches = glob.glob(pattern)
		if matches:
			# pick the most recent file by mtime
			return sorted(matches, key=os.path.getmtime, reverse=True)[0]
	return None


def open_log(path):
	# Open a log file. If the path points to a gzipped file (endswith .gz)
	# open it with gzip in text mode; otherwise open normally.
	if path.endswith('.gz'):
		return gzip.open(path, 'rt', errors='ignore')
	return open(path, 'r', errors='ignore')


def parse_auth_log(path, since_days=None):
	"""Parse one or more auth log files and aggregate failed auth events per IP.

	Parameters:
	- path: a file path or glob pattern (e.g. '/var/log/auth.log*')
	- since_days: if set, only include files with mtime within that many days

	Returns a tuple (total_events, Counter({ip:count}))
	"""
	patterns = [
		re.compile(r'Failed password.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
		re.compile(r'Invalid user.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
		re.compile(r'Failed publickey.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
	]
	counts = collections.Counter()
	total = 0

	# If path is a glob pattern or rotated file, expand to candidates
	paths = [path]
	if any(ch in path for ch in ['*', '?']):
		paths = sorted(glob.glob(path))

	for p in paths:
		try:
			if since_days is not None:
				mtime = os.path.getmtime(p)
				if (time.time() - mtime) > (since_days * 86400):
					continue
			with open_log(p) as fh:
				for line in fh:
					for rx in patterns:
						m = rx.search(line)
						if m:
							ip = m.group(1)
							counts[ip] += 1
							total += 1
							break
		except Exception as e:
			print(f"ERROR: cannot read {p}: {e}", file=sys.stderr)
	return total, counts


def write_report(outpath, data):
	# Write the summary JSON report to disk. Errors are logged but do not
	# interrupt program flow.
	try:
		with open(outpath, "w") as fh:
			json.dump(data, fh, indent=2)
	except Exception as e:
		print(f"WARN: could not write report to {outpath}: {e}", file=sys.stderr)


def main():
	ap = argparse.ArgumentParser(description="Simple SSH auth log analyzer")
	ap.add_argument("--log", "-l", help="Auth log path (auto-detect if omitted)")
	ap.add_argument("--threshold", "-t", type=int, default=10, help="Alert threshold per IP")
	ap.add_argument("--top", type=int, default=10, help="Show top N offending IPs")
	ap.add_argument("--output", "-o", default="log_report.json", help="Output JSON report file")
	ap.add_argument("--since-days", type=int, default=None, help="Only include log files modified within N days (uses file mtime)")
	ap.add_argument("--blocklist-output", help="Write offending IPs (>= threshold) to this file, one per line")
	ap.add_argument("--follow", "-f", action="store_true", help="Follow the log file and stream events in real time")
	ap.add_argument("--auto-block", action="store_true", help="Automatically block offending IPs using chosen method (requires sudo)")
	ap.add_argument("--block-method", choices=["ufw","iptables"], default="ufw", help="Method to use when auto-blocking (ufw or iptables)")
	ap.add_argument("--dry-run", action="store_true", help="If set, show block commands but don't execute them")
	args = ap.parse_args()

	logpath = args.log or detect_auth_log()
	if not logpath:
		print("ERROR: no auth log found (tried /var/log/auth.log and /var/log/secure)")
		sys.exit(1)

	total, counts = parse_auth_log(logpath, since_days=args.since_days)
	top = counts.most_common(args.top)
	flagged = [ {"ip": ip, "count": c} for ip, c in top if c >= args.threshold ]

	summary = {
		"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
		"log_path": logpath,
		"total_failed_events": total,
		"unique_offenders": len(counts),
		"top": [{"ip": ip, "count": c} for ip, c in top],
		"flagged": flagged,
		"threshold": args.threshold,
	}

	write_report(args.output, summary)

	# write blocklist if requested (initial report-time blocklist)
	if args.blocklist_output and flagged:
		try:
			with open(args.blocklist_output, 'w') as bf:
				for e in flagged:
					bf.write(e['ip'] + '\n')
			print(f"Blocklist written to: {args.blocklist_output}")
		except Exception as e:
			print(f"WARN: could not write blocklist: {e}", file=sys.stderr)

	# Print concise human summary
	print(f"Analyzed: {logpath}")
	print(f"Total failed auth events: {total}")
	print(f"Unique offending IPs: {len(counts)}")
	if top:
		print("Top offenders:")
		for ip, c in top:
			note = "ALERT" if c >= args.threshold else ""
			print(f"  {ip}: {c} {note}")
	else:
		print("No failed auth events found in the examined log.")

	if flagged:
		print("\nALERT: The following IPs exceeded the threshold and should be investigated:")
		for e in flagged:
			print(f" - {e['ip']}: {e['count']} attempts")
	else:
		print("\nNo IPs exceeded the threshold.")

	print(f"Report written to: {args.output}")

	# If follow mode requested, stream new events from the specified log. The
	# follow implementation tails the file, reopens on rotation, and prints
	# matching events as they arrive.
	if args.follow:
		print('\nEntering follow mode — streaming new events. Press Ctrl-C to exit.')
		try:
			follow_log(logpath, args.threshold, args.blocklist_output, auto_block=args.auto_block, block_method=args.block_method, dry_run=args.dry_run)
		except KeyboardInterrupt:
			print('\nFollow stopped by user.')


def follow_log(path, threshold, blocklist_output=None, auto_block=False, block_method='ufw', dry_run=False):
	"""Follow a plain-text log file and stream matching auth events.

	The function implements a basic `tail -F` style follow: it seeks to the
	end of the file, reads newly appended lines, and reopens the file if the
	inode changes (rotation). When a matching failed-auth line is seen the
	event is printed and counts are tracked per-IP.

	The `auto_block` option will attempt to block an IP using `ufw` or
	`iptables` when it crosses the configured threshold. Use `--dry-run` to
	preview block commands.
	"""
	import time

	def open_plain(p):
		return open(p, 'r', errors='ignore')

	# patterns to detect
	patterns = [
		re.compile(r'Failed password.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
		re.compile(r'Invalid user.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
		re.compile(r'Failed publickey.*from\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)'),
	]

	counts = collections.Counter()

	# helper to block IPs via system commands. This is intentionally simple
	# and should be audited before enabling in production environments.
	def block_ip(ip):
		if not auto_block:
			return
		cmd = None
		if block_method == 'ufw':
			if shutil.which('ufw') is None:
				print(f"WARN: ufw not available on system; cannot block {ip}")
				return
			cmd = ['sudo', 'ufw', 'deny', 'from', ip]
		elif block_method == 'iptables':
			if shutil.which('iptables') is None:
				print(f"WARN: iptables not available on system; cannot block {ip}")
				return
			cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
		if cmd:
			if dry_run:
				print(f"DRY-RUN: would run: {' '.join(cmd)}")
			else:
				try:
					subprocess.run(cmd, check=True)
					print(f"{GREEN}Blocked {ip} using {block_method}{RESET}")
				except subprocess.CalledProcessError as e:
					print(f"WARN: failed to run block command for {ip}: {e}")

	# ensure file exists
	if not os.path.exists(path):
		print(f"ERROR: follow file not found: {path}")
		return

	fh = open_plain(path)
	# color support
	use_color = sys.stdout.isatty()
	RED = "\u001b[31m" if use_color else ""
	YELLOW = "\u001b[33m" if use_color else ""
	GREEN = "\u001b[32m" if use_color else ""
	RESET = "\u001b[0m" if use_color else ""
	fh.seek(0, os.SEEK_END)
	last_inode = os.fstat(fh.fileno()).st_ino

	while True:
		line = fh.readline()
		if not line:
			# check for rotation (inode change)
			try:
				cur_inode = os.stat(path).st_ino
				if cur_inode != last_inode:
					fh.close()
					fh = open_plain(path)
					last_inode = cur_inode
					print('(log rotated — reopened)')
			except FileNotFoundError:
				# file temporarily missing
				pass
			time.sleep(0.5)
			continue

		# process the incoming line
		matched = False
		for rx in patterns:
			m = rx.search(line)
			if m:
				ip = m.group(1)
				counts[ip] += 1
				matched = True
				# colored alert label when threshold reached
				note = f"{RED}ALERT{RESET}" if counts[ip] >= threshold else ''
				prefix = f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
				if counts[ip] >= threshold:
					print(f"{prefix}  {ip}  count={counts[ip]} {note}  line={line.strip()}")
				else:
					print(f"{prefix}  {ip}  count={counts[ip]}   line={line.strip()}")

				# write blocklist immediately when threshold crossed
				if blocklist_output and counts[ip] == threshold:
					try:
						with open(blocklist_output, 'a') as bf:
							bf.write(ip + '\n')
						print(f"{YELLOW}Wrote {ip} to blocklist: {blocklist_output}{RESET}")
					except Exception as e:
						print(f"WARN: could not write blocklist: {e}")

				# attempt auto-block when threshold is crossed
				if counts[ip] == threshold and 'block_ip' in globals():
					try:
						# block_ip is defined in the module scope; call if auto-block was enabled
						block_ip(ip)
					except Exception as e:
						print(f"WARN: auto-block failed for {ip}: {e}")
				break
		if not matched:
			# non-matching lines are ignored in follow mode
			pass


if __name__ == '__main__':
	main()


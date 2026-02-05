# Lab Documentation and TODO

## Todo (this document)
- [x] Create `LAB_DOCUMENTATION.md` with analysis, changes, tests, and run instructions
- [ ] Archive or version the starter scripts as needed

---

## Summary
This document captures the analysis and modifications performed on the starter scripts in the workspace for Lab 1 and Lab 2.

Files examined:
- `starter_linux_security_check.sh`
- `starter_log_analyzer.py`
- `starter_password_checker.py`

## Analysis — `starter_linux_security_check.sh`
- Inputs: reads `/var/log/auth.log` or `/var/log/secure`, `/etc/ssh/sshd_config`, and `/etc/passwd` (no interactive input).
- Outputs: prints status lines to stdout with security-focused messages.
- Variables: `THRESHOLD_FAILED`, `AUTH_LOG`, `FAILED_COUNT`, `SSHD_CONFIG`, `PERMIT_ROOT`, `UID0_USERS`.
- Conditions: compares `FAILED_COUNT` against `THRESHOLD_FAILED`; checks `PermitRootLogin` setting; checks number of UID 0 accounts.
- Short description: quick host audit for failed SSH logins, insecure root SSH login config, and extra UID 0 users.
- Security use case: quick detection of brute-force attempts and insecure SSH configuration.
- Limitation / risk: relies on log file locations and read permissions; may miss events if logs are rotated, inaccessible, or use different messages; false negatives possible.

## Analysis — `starter_log_analyzer.py`
- Inputs: none (placeholder).
- Outputs: prints a stub message.
- Short description: placeholder for a log analysis tool; no parsing implemented.
- Security use case: could be extended to parse logs for suspicious events and alerting.
- Limitation / risk: currently non-functional.

## Analysis — `starter_password_checker.py`
- Inputs: user input via `input()` (password typed visibly).
- Outputs: prints the entered password's length.
- Short description: basic password length checker.
- Security use case: can provide simple password policy feedback.
- Limitation / risk: insecure UX (password entered in clear), not using masked input, no strength checks, no rate-limiting, and no secure handling/storage.

## Changes made (Lab 2 modifications)
Modified file: `starter_linux_security_check.sh`

- Added comments explaining purpose and major sections.
- Introduced a configurable threshold (`THRESHOLD_FAILED=5`) for failed SSH authentication attempts.
- Added detection for the correct auth log path (`/var/log/auth.log` or `/var/log/secure`).
- Added counting of failed SSH attempts and comparison to threshold with an alert message when exceeded.
- Added parsing of `/etc/ssh/sshd_config` to evaluate `PermitRootLogin` and print a warning if enabled.
- Added check for multiple UID 0 accounts in `/etc/passwd` and alert if more than just `root` exists.

### Script behavior after modification
- Prints the detected auth log path or 'not found'.
- Prints the failed SSH auth count and an ALERT if the count >= threshold.
- Prints a WARNING if `PermitRootLogin` is `yes`, otherwise prints OK or NOTICE if file not found.
- Prints ALERT if multiple UID 0 users exist.

## Test and run instructions
To run the modified script locally:

```bash
cd /home/evaristo/Documents/scripting_for_security
bash starter_linux_security_check.sh
```

Observed test output from running the script in this environment:

```
Security check - quick system audit
Auth log: /var/log/auth.log
Failed SSH auth attempts: 0
OK: Failed SSH attempts below threshold (5).
NOTICE: /etc/ssh/sshd_config not found — cannot evaluate root SSH login setting.
OK: Only 'root' has UID 0.
```

Note: On other systems, `/etc/ssh/sshd_config` may be present and `PermitRootLogin` may be set differently; the script's messages will reflect that.

## How the changes improve security
- Automates checks for common SSH-related misconfigurations and suspicious auth activity.
- Alerts are tunable via `THRESHOLD_FAILED` and provide actionable guidance (investigate brute-force, disable root login).

## Remaining limitations & suggestions
- The script needs appropriate permissions to read logs and config files; run as a privileged user or with sudo where required.
- Auth log parsing is simplistic (counts lines matching "Failed password"). Consider improving detection by parsing timestamps, per-IP counts, and handling rotated logs.
- Add logging of script output to a file for historical tracking or integrate with a SIEM/alerting system.
- Consider extending `starter_log_analyzer.py` into a working parser and `starter_password_checker.py` to use masked input and strength checks.

## Log analyzer (`starter_log_analyzer.py`) — details and sample report

- Purpose: parse system auth logs to summarize failed SSH authentication attempts per source IP and produce a JSON report for alerting or further processing.
- Key features implemented:
	- Auto-detects auth log file (`/var/log/auth.log` or `/var/log/secure`).
	- Uses regexes to capture failed password, invalid user, and failed publickey lines and extract source IPs.
	- Aggregates counts per IP and writes a summary JSON report (`log_report.json`).
	- Prints a concise human-readable summary to stdout and flags IPs exceeding a per-IP threshold.

### How to run the analyzer
```bash
python3 starter_log_analyzer.py --threshold 5 --top 10 --output log_report.json
```

### Sample produced `log_report.json` (from this run):

```json
{
	"timestamp": "2026-02-05T11:28:04.014425Z",
	"log_path": "/var/log/auth.log",
	"total_failed_events": 0,
	"unique_offenders": 0,
	"top": [],
	"flagged": [],
	"threshold": 5
}
```

Notes:
- When run on systems with active attacks, `total_failed_events` and `top` will show offending IPs and counts.
- The analyzer is intentionally simple; for production use, consider parsing rotated logs, adding time-window filters, and exporting to SIEM.

### Enhancements added
- Rotated and gzipped log support: analyzer now accepts rotated log files (e.g., `/var/log/auth.log.1` or `.gz`) and will read gzipped files.
- `--since-days` option: only include log files modified within the given number of days (based on file mtime). Useful for time-window limited scanning.
- `--blocklist-output` option: write offending IPs (those exceeding threshold) to a plain text blocklist file (one IP per line) for integration with blocking tools.

### Tests & runner
- Unit tests added under `tests/` for both the analyzer and password checker.
- Run tests with:

```bash
./run_tests.sh
```

### Files added
- `archive/2026-02-05_11-28_*` — backups of original starter scripts
- `tests/sample_auth.log` — sample input for tests
- `tests/test_log_analyzer.py`, `tests/test_password_checker.py` — unit tests
- `run_tests.sh` — test runner
- `requirements.txt` — dependency manifest (empty)

## Archive
- Originals of the starter scripts were saved to the `archive/` directory with a timestamped prefix:
	- `archive/2026-02-05_11-28_starter_linux_security_check.sh`
	- `archive/2026-02-05_11-28_starter_log_analyzer.py`
	- `archive/2026-02-05_11-28_starter_password_checker.py`

## `starter_password_checker.py` (hardened)
- Now uses masked input via `getpass` and performs simple strength checks (length, character classes) and an estimated entropy calculation.
- Usage:

```bash
python3 starter_password_checker.py
```

The script will prompt for the password (masked), then print a short strength report and suggestions.

## `starter_log_analyzer.py` — running examples

- Basic run (auto-detect log):

```bash
python3 starter_log_analyzer.py --threshold 5 --top 10 --output log_report.json
```

- Include rotated logs modified within the last 2 days and write a blocklist for offending IPs:

```bash
python3 starter_log_analyzer.py --log '/var/log/auth.log*' --since-days 2 --threshold 5 --top 20 --output recent_report.json --blocklist-output blocklist.txt
```

Notes:
- The `--log` path can be a glob (e.g., `/var/log/auth.log*`) and gzipped rotated logs will be read.
- `--since-days` filters files by mtime which is a fast heuristic for recent logs; for robust time-based filtering consider parsing timestamps inside log lines.

## Tests
- Run the provided test runner to execute unit tests for both the analyzer and the password checker:

```bash
./run_tests.sh
```

If you prefer to run discovery manually from the project root, the equivalent command is:

```bash
python3 -m unittest discover -v tests
```

---


---

## Next steps (optional)
- [ ] Extend `starter_log_analyzer.py` into a Python log parser (filter by date, severity, detect anomalies).
- [ ] Improve `starter_password_checker.py` to use `getpass` for masked input and add entropy-based strength checks.
- [ ] Add unit tests for parsing functions and a small CI job to run checks.

## Follow mode and auto-blocking (new)

- `--follow` (`-f`): stream matching auth events from a log file in real time. Useful for monitoring during incident response or live demonstrations. The analyzer tails the file, reopens on rotation, and prints each matching event as it arrives.
- Colored alerts: when stdout is a TTY, the analyzer prints `ALERT` in red for IPs that meet or exceed the configured threshold.
- `--blocklist-output`: append offending IPs (when they cross the threshold) to a plain text file, one IP per line.
- `--auto-block`: optionally attempt to block offending IPs automatically when they hit the threshold. Supported methods:
	- `--block-method ufw` — uses `sudo ufw deny from <ip>` (recommended when `ufw` is available).
	- `--block-method iptables` — uses `sudo iptables -A INPUT -s <ip> -j DROP`.
- `--dry-run`: show the block command that would be executed without running it. Always test with `--dry-run` first.

Usage examples (follow mode):

```bash
# follow and write blocklist when threshold crossed
python3 starter_log_analyzer.py --log /var/log/auth.log --follow --threshold 5 --blocklist-output blocklist.txt

# follow and show block commands but don't execute them
python3 starter_log_analyzer.py --log /var/log/auth.log --follow --threshold 5 --auto-block --block-method iptables --dry-run

# follow and actually block using ufw (requires sudo and ufw installed)
sudo python3 starter_log_analyzer.py --log /var/log/auth.log --follow --threshold 5 --auto-block --block-method ufw
```

Safety notes:
- Auto-blocking requires elevated privileges and can disrupt legitimate access if thresholds are set too low — always test with `--dry-run` and monitor the blocklist before enabling real blocks.
- The script writes to the blocklist file when an IP crosses the threshold; automated integration with firewall tools is intentionally conservative (blocks occur when threshold is reached).
- For production deployments, consider integrating with a proven tool like `fail2ban` or a centralized firewall/orchestration system that supports whitelists, rate limits, and block expiration.

## Preparing for publishing / secret-safety checklist

Before pushing this repository to a public Git hosting service, follow these steps to avoid leaking secrets or runtime artifacts:

1. Scan the repository for secrets using automated tools (e.g., `git-secrets`, `truffleHog`, or `gitleaks`).
2. Remove runtime artifacts (reports, blocklists, temporary logs). This repository now ignores `*_report.json` and `*_blocklist*.txt`; review `.gitignore`.
3. If you accidentally committed secrets, remove them from history using `git filter-repo` or the BFG repo-cleaner; after rewriting history, force-push and rotate any exposed credentials.
4. Use GitHub Secrets / Actions encrypted variables for credentials in CI rather than committing them.
5. Consider adding `SECURITY.md` and `CODE_OF_CONDUCT.md` for public projects.

If you'd like, I can prepare a sanitized branch or a script that prunes runtime files and helps you run `gitleaks` locally — tell me which option you prefer.

## Code comments added

I added explanatory comments and docstrings across the main files to make the code easier to read and maintain. Files updated with comments include:

- `starter_linux_security_check.sh` — header comments describing purpose, checks, and usage notes.
- `starter_log_analyzer.py` — expanded module docstring, comments on functions (`detect_auth_log`, `open_log`, `parse_auth_log`, `follow_log`), and inline notes for the auto-block helper.
- `starter_password_checker.py` — module docstring and comments for `estimate_entropy`, `analyze`, `print_report`, and `main`.
- `run_tests.sh` — script header explaining its purpose and behaviour.
- `tests/test_log_analyzer.py`, `tests/test_password_checker.py` — brief headers describing what each unit test validates.

These comments are intentionally concise and focused on explaining the purpose, inputs, outputs, and any safety or permission considerations for each component.


---
Generated on 2026-02-05.

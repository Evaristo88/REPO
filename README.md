# Scripting for Security — Starter Lab

This repository contains simple, educational scripts and tools used for a security scripting lab:

- `starter_linux_security_check.sh` — quick host audit for SSH failures, root-login config, and UID 0 accounts.
- `starter_log_analyzer.py` — Python auth-log parser with reporting, follow (real-time) mode, blocklist output, and optional auto-blocking (dry-run supported).
- `starter_password_checker.py` — interactive password checker with masked input and simple strength heuristics.
- `login.html` / `styles.css` — small demo login page and styles (static frontend only).
- `tests/` — unit tests and sample logs.
- `LAB_DOCUMENTATION.md` — analysis, change log, and usage notes for the lab.

## Requirements

- Python 3.8+ (standard library only; no external packages required).
- `sudo` and `ufw` or `iptables` only if you plan to enable auto-blocking (see safety notes).

## Quick start

Clone or open the repository, then run the components from the repository root.

Run the simple host audit:

```bash
bash starter_linux_security_check.sh
```

Run the log analyzer (example):

```bash
# analyze and write a JSON report
python3 starter_log_analyzer.py --threshold 5 --top 10 --output log_report.json

# follow a log in real time (no blocking)
python3 starter_log_analyzer.py --log /var/log/auth.log --follow --threshold 5 --blocklist-output blocklist.txt

# follow with dry-run auto-block commands (safe preview)
python3 starter_log_analyzer.py --log /var/log/auth.log --follow --threshold 5 --auto-block --block-method iptables --dry-run
```

Run the interactive password checker:

```bash
python3 starter_password_checker.py
```

Preview the static login page locally:

```bash
python3 -m http.server 8000
# then open http://localhost:8000/login.html in your browser
```

Run unit tests:

```bash
./run_tests.sh
```

## Safety notes

- The auto-block feature in `starter_log_analyzer.py` requires `sudo` privileges and will modify system firewall rules when enabled. Always test with `--dry-run` first and use conservative thresholds.
- The scripts are educational examples — they are not hardened production-grade tools. For production blocking and rate-limiting, consider tools like `fail2ban` or centralized SIEM + orchestration.

## Contributing / Next steps

- Add time-window parsing, rotated log timestamp parsing, and configurable block expiration.
- Add CI that runs `./run_tests.sh` and verifies basic linting.

---
Generated: 2026-02-05

## Features & CLI reference

### `starter_log_analyzer.py`
- Purpose: parse auth logs, summarize failed SSH attempts per IP, stream live events, and optionally write a blocklist or auto-block.
- Useful flags:
	- `--log <path|glob>` : path or glob to auth logs (auto-detects if omitted)
	- `--threshold <n>`   : per-IP alert threshold (default 10)
	- `--top <n>`         : show top N offending IPs (default 10)
	- `--output <file>`   : write JSON report (default `log_report.json`)
	- `--blocklist-output <file>` : append offending IPs when threshold crossed
	- `--follow` or `-f`  : follow a log file and stream matching events in real time
	- `--auto-block`      : attempt to block offending IPs (requires sudo; use with care)
	- `--block-method`    : `ufw` or `iptables` when using `--auto-block`
	- `--dry-run`         : show block commands without executing them

Example:
```bash
python3 starter_log_analyzer.py --log '/var/log/auth.log*' --since-days 1 --threshold 5 --top 20 --output recent.json --blocklist-output blocked.txt
```

### `starter_password_checker.py`
- Prompts (masked) for a password and reports: length, character classes, simple entropy estimate, and suggestions.

Example:
```bash
python3 starter_password_checker.py
```

### `starter_linux_security_check.sh`
- Shell script that performs a quick host audit: failed SSH auth count, `PermitRootLogin`, and UID 0 users.

## Testing & CI

- Unit tests live in `tests/`. Run them locally with:

```bash
./run_tests.sh
```

- For CI, run the same script and add a step to fail the build if tests fail.

## Publishing to GitHub

If you wish to push this repo to GitHub, these example commands will create a repo locally and push the current files (run on your machine where `git` is available):

```bash
git init
git add .
git commit -m "Initial lab scripts and tools"
gh repo create my-security-lab --public --source=. --remote=origin  # requires GitHub CLI
git push -u origin main
git tag -a v0.1.0 -m "v0.1.0 initial lab release"
git push origin v0.1.0
```

If you don't have the GitHub CLI, create a remote repository in the GitHub web UI and push using the `git remote add` URL step instead.

## Contributing

- Suggested workflow: create feature branches, add tests for new behavior, run `./run_tests.sh`, and open pull requests for review.

---

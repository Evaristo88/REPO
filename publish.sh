#!/usr/bin/env bash
set -euo pipefail

# Helper script to prepare and push a release tag to a remote repository.
# This script just runs a safe set of commands; review before running.

if ! command -v git >/dev/null 2>&1; then
  echo "git not found — run these commands manually on your machine where git is available:" >&2
  echo
  echo "  git init"
  echo "  git add ."
  echo "  git commit -m 'Initial lab scripts and tools'"
  echo "  git remote add origin <your-remote-url>"
  echo "  git push -u origin main"
  echo "  git tag -a v0.1.0 -m 'v0.1.0'"
  echo "  git push origin v0.1.0"
  exit 1
fi

echo "Staging files..."
git add .
git commit -m "Prepare release v0.1.0" || echo "No changes to commit"

echo "Create annotated tag v0.1.0"
git tag -a v0.1.0 -m "v0.1.0"

echo "Push to origin (ensure remote is configured)"
git push origin --tags

echo "Done."

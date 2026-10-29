#!/usr/bin/env bash
# Local Jobops bootstrap. Candidate data is never created in this repository.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        echo "Use setup.ps1 from PowerShell on Windows." >&2
        exit 1
        ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.11 or newer is required." >&2
    exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    echo "Python 3.11 or newer is required." >&2
    exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m playwright install chromium

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Dependencies installed. Use setup.ps1 on Windows for initialization with Windows Credential Manager."
    echo "Linux can install dependencies, but Jobops has no Linux production credential-store backend."
    echo "Run the offline test suite with: .venv/bin/python -m pytest -q"
    exit 0
fi

.venv/bin/python jobctl.py init

echo "Jobops is ready. Private data lives outside this checkout."
echo "Migrate an existing workflow with:"
echo "  .venv/bin/python jobctl.py migrate /path/to/applypilot-workflow --legacy-profile /path/to/ignored/profile.yaml"
echo "Then inspect the queue with: .venv/bin/python jobctl.py queue --list"

#!/usr/bin/env bash
set -euo pipefail

REPO_NAME="bchoc"
ROOT_DIR="$PWD/$REPO_NAME"

mkdir -p "$ROOT_DIR"
cd "$ROOT_DIR"

mkdir -p core chain persistence utils tests packages

write_py() {
    local path="$1"
    local msg="$2"
    mkdir -p "$(dirname "$path")"
    echo "print(\"This is the $msg file\")" > "$path"
}

write_py bchoc.py "bchoc.py"
write_py cli.py "cli.py"

write_py core/commands.py "core/commands.py"
write_py core/validators.py "core/validators.py"
write_py core/security.py "core/security.py"

write_py chain/blockchain.py "chain/blockchain.py"

write_py persistence/persistence.py "persistence/persistence.py"

write_py utils/timefmt.py "utils/timefmt.py"
write_py utils/errors.py "utils/errors.py"
write_py utils/block.py "utils/block.py"

write_py tests/test_placeholder.py "tests/test_placeholder.py"

cat > Makefile <<'MK'
.PHONY: test

test:
	@echo "This is the Makefile (test target)"
MK

cat > .gitignore <<'GI'
__pycache__/
*.pyc
.env
venv/
build/
dist/
packages/
GI

cat > README.md <<'MD'
# bchoc

Minimal project skeleton.

Each `.py` file just prints its own name when run.
MD

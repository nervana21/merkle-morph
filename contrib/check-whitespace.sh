#!/usr/bin/env bash
#
# Check for whitespace issues in Rust files, including trailing blank lines at EOF.
# This matches the behavior of git diff-index --check.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
cd "$REPO_DIR"

# Find all Rust files in the repository (exclude corpus/ and target/ directories)
rust_files=$(find . -name "*.rs" -type f ! -path "./target/*" ! -path "./corpus/*" ! -path "*/target/*" | sort)

errors=0

check_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        return
    fi

    # Check for trailing blank lines (more than one newline at EOF)
    # Git's --check flag detects "new blank line at EOF" when there are multiple trailing newlines
    # We want exactly one newline at the end of the file

    # Check if file ends with multiple newlines by examining the last few bytes
    # Read last 10 bytes and convert to hex
    local last_bytes=$(tail -c 10 "$file" | od -An -tx1 | tr -d ' \n')

    # Check if file ends with \n\n (two consecutive newlines = 0a0a)
    # This matches git diff-index --check behavior for "new blank line at EOF"
    if echo "$last_bytes" | grep -qE "0a0a"; then
        echo "Error: $file: new blank line at EOF"
        errors=$((errors + 1))
    fi

    # Also check for trailing whitespace on lines (spaces or tabs before newline)
    # Use grep to find lines with trailing whitespace and show line numbers
    local trailing_ws=$(grep -Hn '[[:space:]]$' "$file" 2>/dev/null || true)
    if [ -n "$trailing_ws" ]; then
        echo "Error: $file: trailing whitespace found:"
        echo "$trailing_ws" | sed 's/^/  /'
        errors=$((errors + 1))
    fi
}

# Check each Rust file
while IFS= read -r file; do
    if [ -n "$file" ]; then
        check_file "$file"
    fi
done <<EOF
$rust_files
EOF

if [ $errors -gt 0 ]; then
    echo ""
    echo "Found $errors whitespace error(s). Fix them before committing."
    exit 1
fi

exit 0

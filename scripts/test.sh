#!/bin/sh
set -eu

if [ -n "${BNPYTHON:-}" ]; then
    bnpython=$BNPYTHON
elif command -v bnpython3 >/dev/null 2>&1; then
    bnpython=$(command -v bnpython3)
elif [ -x "/Applications/Binary Ninja.app/Contents/MacOS/bnpython3" ]; then
    bnpython="/Applications/Binary Ninja.app/Contents/MacOS/bnpython3"
else
    echo "Could not find bnpython3." >&2
    echo "Set BNPYTHON to the Binary Ninja Python launcher path and try again." >&2
    exit 1
fi

echo "Using Binary Ninja Python: $bnpython"
BN_DISABLE_USER_PLUGINS=1 "$bnpython" -m unittest discover -v

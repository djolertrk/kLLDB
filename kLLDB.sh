#!/bin/bash
SCRIPT_DIR="$(dirname "$0")"
PYTHON_SCRIPT="$SCRIPT_DIR/kLLDB.py"

# Launch LLDB and import the initialization script
lldb -o "command script import $PYTHON_SCRIPT" "$@"


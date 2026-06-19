#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$PROJECT_DIR/venv/bin/python" "$PROJECT_DIR/spider_eye.py" "$@"

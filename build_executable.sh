#!/bin/bash

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Run ./install.sh first."
    exit 1
fi

echo "[*] Building SPIDER-EYE executable..."

source venv/bin/activate
pip install pyinstaller

pyinstaller \
  --onefile \
  --name spider-eye \
  --clean \
  spider_eye.py

echo ""
echo "[+] Build completed."
echo "[+] Executable: dist/spider-eye"
echo "[!] Nmap must still be installed on the system."

#!/bin/bash

set -e

echo "[*] SPIDER-EYE installer"
echo "[*] Installing system dependencies and Python libraries..."

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v apt >/dev/null 2>&1; then
    echo "[*] Detected apt-based system"
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv nmap
elif command -v dnf >/dev/null 2>&1; then
    echo "[*] Detected dnf-based system"
    sudo dnf install -y python3 python3-pip nmap
elif command -v pacman >/dev/null 2>&1; then
    echo "[*] Detected pacman-based system"
    sudo pacman -Sy --noconfirm python python-pip nmap
else
    echo "[!] Unsupported package manager."
    echo "[!] Install manually: python3, pip/venv and nmap."
    exit 1
fi

echo "[*] Creating Python virtual environment..."
python3 -m venv "$PROJECT_DIR/venv"

echo "[*] Installing Python requirements..."
"$PROJECT_DIR/venv/bin/pip" install --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

echo "[*] Creating local launcher..."
cat > "$PROJECT_DIR/run.sh" <<EOF
#!/bin/bash
PROJECT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
"\$PROJECT_DIR/venv/bin/python" "\$PROJECT_DIR/spider_eye.py" "\$@"
EOF

chmod +x "$PROJECT_DIR/run.sh"

echo "[*] Creating global command: spider-eye"
sudo ln -sf "$PROJECT_DIR/run.sh" /usr/local/bin/spider-eye

echo ""
echo "[+] Installation completed."
echo ""
echo "Run interactive mode:"
echo "  spider-eye"
echo ""
echo "Example CLI:"
echo "  spider-eye -t 192.168.50.20 -m service -p top1000"
echo ""
echo "For UDP/OS/full audit scans, use sudo when needed:"
echo "  sudo spider-eye -t 192.168.50.20 -m udp -p 53,111,137,138,2049 -y"

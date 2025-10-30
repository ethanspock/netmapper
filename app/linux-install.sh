#!/usr/bin/env bash
set -euo pipefail

VENV_NAME=".venv"

have() { command -v "$1" >/dev/null 2>&1; }

sudo_cmd() {
  if [ "$EUID" -ne 0 ]; then echo sudo "$@"; else echo "$@"; fi
}

install_pkgs() {
  if have apt-get; then
    $(sudo_cmd apt-get) update
    $(sudo_cmd apt-get) install -y python3 python3-venv python3-pip libpcap0.8 tcpdump nmap dnsutils avahi-utils samba-common-bin
  elif have dnf; then
    $(sudo_cmd dnf) install -y python3 python3-pip python3-virtualenv libpcap tcpdump nmap bind-utils avahi samba-client
  elif have yum; then
    $(sudo_cmd yum) install -y python3 python3-pip python3-virtualenv libpcap tcpdump nmap bind-utils avahi samba-client
  elif have pacman; then
    $(sudo_cmd pacman) -Syu --noconfirm
    $(sudo_cmd pacman) -S --noconfirm python python-pip python-virtualenv libpcap tcpdump nmap bind avahi samba
  elif have zypper; then
    $(sudo_cmd zypper) install -y python3 python3-pip python3-virtualenv libpcap1 tcpdump nmap bind-utils avahi samba-client
  else
    echo "Unsupported package manager. Please install: python3, python3-venv, python3-pip, libpcap, tcpdump, nmap, dig/nslookup, avahi, samba tools." >&2
  fi
}

echo "Installing system packages (you may be prompted for sudo)..."
install_pkgs

echo "Creating virtual environment: ${VENV_NAME}"
python3 -m venv "${VENV_NAME}"
source "${VENV_NAME}/bin/activate"

echo "Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements-linux.txt

echo "Optional: allow capture without sudo (may require reinstall if python path changes)"
if have setcap && have readlink; then
  PYBIN="$(readlink -f "$(command -v python3)")"
  echo "Run to allow non-root capture: sudo setcap cap_net_raw,cap_net_admin=eip ${PYBIN}"
fi

echo "Done. Start the app with:"
echo "source ${VENV_NAME}/bin/activate && python app.py"

#!/usr/bin/env bash
# Verify the Linux host has everything needed to run the experiment matrix.
# Exits 0 on success; non-zero on any missing dependency.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

OK=0
FAIL=0

check_cmd() {
  local name="$1" hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    printf "[ OK ] %-20s (%s)\n" "$name" "$(command -v "$name")"
    OK=$((OK + 1))
  else
    printf "[FAIL] %-20s  %s\n" "$name" "$hint"
    FAIL=$((FAIL + 1))
  fi
}

check_py() {
  local mod="$1" hint="$2"
  if python3 -c "import $mod" >/dev/null 2>&1; then
    printf "[ OK ] python:%-14s (import works)\n" "$mod"
    OK=$((OK + 1))
  else
    printf "[FAIL] python:%-14s  %s\n" "$mod" "$hint"
    FAIL=$((FAIL + 1))
  fi
}

echo "== System commands =="
check_cmd sudo                "required: install sudo"
check_cmd python3             "required: apt install python3"
check_cmd mn                  "required: apt install mininet"
check_cmd ovs-vsctl           "required: apt install openvswitch-switch"
check_cmd ovs-ofctl           "required: apt install openvswitch-switch"
check_cmd os-ken-manager      "required: pip install os-ken"
check_cmd ss                  "recommended: iproute2 (for socket readiness probe)"

echo
echo "== Python modules =="
check_py yaml                 "pip install pyyaml"
check_py scapy                "pip install scapy"
check_py matplotlib           "pip install matplotlib"
check_py psutil               "pip install psutil (controller CPU/mem metrics)"
check_py mininet              "apt install mininet (Python bindings)"
check_py os_ken               "pip install os-ken"

echo
echo "== Kernel modules =="
if lsmod 2>/dev/null | grep -q openvswitch; then
  echo "[ OK ] openvswitch kernel module loaded"
  OK=$((OK + 1))
else
  if modinfo openvswitch >/dev/null 2>&1; then
    echo "[WARN] openvswitch module not loaded; run: sudo modprobe openvswitch"
  else
    echo "[FAIL] openvswitch module not available; install openvswitch-switch"
    FAIL=$((FAIL + 1))
  fi
fi

echo
echo "== Privileges =="
if [[ $EUID -eq 0 ]]; then
  echo "[ OK ] running as root"
else
  echo "[INFO] not running as root; the run_*.sh scripts require 'sudo -E'."
fi

echo
echo "summary: ok=$OK fail=$FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo "environment is NOT ready; fix the FAIL entries above."
  exit 1
fi
echo "environment is ready."

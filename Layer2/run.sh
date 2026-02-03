#!/bin/bash
set -e

# ---------------- CONFIG ----------------
APP=eBPFAgent
APP_DIR="$(dirname "$0")"      # Layer2 folder
VMLINUX=/sys/kernel/btf/vmlinux
VMLINUX_H="$APP_DIR/vmlinux.h"

# ---------------- ROOT CHECK ----------------
echo "[+] Checking root..."
if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo)"
    exit 1
fi

# ---------------- GENERATE VMLINUX.H ----------------
echo "[+] Generating vmlinux.h (if missing)..."
if [ ! -f "$VMLINUX_H" ]; then
    bpftool btf dump file $VMLINUX format c > $VMLINUX_H
fi

# ---------------- COMPILE BPF PROGRAM ----------------
echo "[+] Compiling BPF program..."
clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I"$APP_DIR" \
    -c "$APP_DIR/$APP.bpf.c" \
    -o "$APP_DIR/$APP.bpf.o"

# ---------------- GENERATE SKELETON ----------------
echo "[+] Generating skeleton..."
bpftool gen skeleton "$APP_DIR/$APP.bpf.o" > "$APP_DIR/$APP.skel.h"



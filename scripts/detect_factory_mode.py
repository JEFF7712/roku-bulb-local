#!/usr/bin/env python3
"""Passive factory-mode detector for Roku RK_BA19C vs Wyze WLPA19CV2 behavior.

Listen-only by default. This never sends `hap upgrade` unless --probe is passed,
and even then it only probes a single explicit IP you provide.

What it does:
1. Listens on UDP 22223 for factory-test broadcasts (Wyze bulbs emit
   self-describing bursts about every 2s in FAC TEST, including model info).
2. Optionally sends one benign `hap help`-style probe to a target IP with --probe
   to check for any UDP reply without triggering OTA. No upgrade URL is ever sent
   by this script.
3. Logs everything with timestamps to stdout plus optional file.

Usage:
  python3 detect_factory_mode.py --listen 0.0.0.0 --port 22223
  python3 detect_factory_mode.py --log captures/factory-listen.log
  python3 detect_factory_mode.py --probe 192.168.3.100  # active, single host only

Run this on a machine on the same L2 as the hijack AP while power cycling.
Correlate power-cycle count with first broadcast packet.
"""
from __future__ import annotations

import argparse
import datetime
import socket
import sys


def log(msg: str, fh=None) -> None:
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def listen(bind: str, port: int, fh=None) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    s.bind((bind, port))
    s.settimeout(1.0)
    log(f"listening on UDP {bind}:{port} (passive, no packets sent)", fh)
    log("now power cycle the bulb: on until green fade, off 5s, repeat to ~17", fh)
    seen: set[tuple[str, int]] = set()
    try:
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            key = (addr[0], addr[1])
            first = key not in seen
            seen.add(key)
            printable = data.decode("utf-8", errors="replace").strip()
            hexhead = data[:64].hex()
            tag = "FIRST-SEEN" if first else "repeat"
            log(f"{tag} from {addr[0]}:{addr[1]} len={len(data)} text={printable!r} hex={hexhead}", fh)
            lowered = printable.lower()
            for marker in ("hap", "fac", "wyze", "rk_ba19c", "wlpa19", "upgrading", "model"):
                if marker in lowered:
                    log(f"  -> marker {marker!r} present", fh)
    except KeyboardInterrupt:
        log(f"stopped. unique senders: {len(seen)}", fh)
        return 0


def probe(target: str, port: int, fh=None) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    msg = b"hap"
    log(f"sending benign probe {msg!r} to {target}:{port} (no upgrade URL, single packet)", fh)
    s.sendto(msg, (target, port))
    try:
        data, addr = s.recvfrom(4096)
        log(f"reply from {addr}: {data!r}", fh)
        return 0
    except socket.timeout:
        log("no reply (expected on stock firmware; factory mode would answer)", fh)
        return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--listen", default="0.0.0.0", help="bind address for passive listen")
    p.add_argument("--port", type=int, default=22223, help="factory UDP port")
    p.add_argument("--log", default=None, help="append log file")
    p.add_argument("--probe", default=None, metavar="IP", help="active single-host probe (no OTA)")
    p.add_argument("--no-listen", action="store_true", help="skip listen phase when probing")
    args = p.parse_args(argv)

    fh = open(args.log, "a", encoding="utf-8") if args.log else None
    try:
        if args.probe:
            rc = probe(args.probe, args.port, fh)
            if args.no_listen:
                return rc
            log("entering passive listen after probe", fh)
        return listen(args.listen, args.port, fh)
    finally:
        if fh:
            fh.close()


if __name__ == "__main__":
    sys.exit(main())

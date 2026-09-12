#!/usr/bin/env python3
"""Send an encrypted local command to a Roku/Wyze bulb on port 88.

Protocol: AES-CBC (key=IV=enr), PKCS7 pad, base64, compact JSON.
POST http://<ip>:88/device_request {request,set_status,isSendQueue,characteristics}

Secrets (enr) come from env, never from files:
  BULB_ENR=<16-char enr> python3 local_set.py <ip> <mac> P1501 50

Ref: docs/local-http-api.md
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request


def encrypt_characteristics(enr: str, mac: str, plist: list[dict[str, str]]) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from base64 import b64encode

    inner = json.dumps(
        {"mac": mac, "index": "0", "ts": str(int(time.time() * 1000)), "plist": plist},
        separators=(",", ":"),
    )
    key = enr.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    return b64encode(cipher.encrypt(pad(inner.encode("utf-8"), AES.block_size))).decode()


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("usage: BULB_ENR=<enr> local_set.py <ip> <mac> <pid> <pvalue>", file=sys.stderr)
        return 1
    ip, mac, pid, pvalue = argv[1], argv[2], argv[3], argv[4]
    enr = os.environ.get("BULB_ENR", "")
    if len(enr) != 16:
        print("BULB_ENR must be the 16-char enr", file=sys.stderr)
        return 1
    body = json.dumps(
        {
            "request": "set_status",
            "isSendQueue": 0,
            "characteristics": encrypt_characteristics(enr, mac, [{"pid": pid, "pvalue": pvalue}]),
        }
    ).encode()
    req = urllib.request.Request(
        f"http://{ip}:88/device_request", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"http={resp.status} bytes={len(resp.read())}")
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

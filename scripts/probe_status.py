#!/usr/bin/env python3
"""Investigate local state synchronization on Roku/Wyze bulbs (BC1000X / RK_BA19C).

Implements a 5-step controlled experiment:
  1. Positive control: verified set_status to confirm reachability.
  2. Header isolation: test Root-Response (omitted, '0', '1') and Mesh-Node-Mac.
     Note: In ESP-MDF mlink_httpd.c, Root-Response: 1 sets resp=false (suppressing
     device responses), whereas omitted/0 leaves resp=true.
  3. Encrypted reads & ESP-MDF Mlink schemas: get_status (plist, cids) & get_device_info.
  4. Passive LAN notifications: listens for UDP broadcasts (port 1025 mlink_notice, etc.).
  5. Result classification: categorize empty, data, error, timeout, or malformed replies.

Usage:
  BULB_ENR=<16-char enr> python3 scripts/probe_status.py <ip> <mac> [--listen-udp [seconds]]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DEFAULT_PORT = 88
MLINK_NOTICE_PORT = 1025
FACTORY_UDP_PORT = 22223


def encrypt_payload(enr: str, payload: dict[str, Any], pad_mode: str = "pkcs7") -> str:
    """Encrypt inner dictionary with AES-128-CBC using enr as key and IV."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if pad_mode == "zero":
        rem = len(raw) % 16
        padded = raw if rem == 0 else raw + b"\x00" * (16 - rem)
    else:
        padded = pad(raw, 16)
    key = enr.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    return base64.b64encode(cipher.encrypt(padded)).decode("ascii")


def decrypt_response(enr: str, ciphertext_b64: str) -> str:
    """Attempt AES-128-CBC decryption of returned characteristics."""
    raw = base64.b64decode(ciphertext_b64.strip())
    key = enr.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, key)
    dec = cipher.decrypt(raw)
    try:
        return unpad(dec, 16).decode("utf-8", errors="replace")
    except ValueError:
        return dec.rstrip(b"\x00").decode("utf-8", errors="replace")


def send_probe(
    ip: str,
    body_dict: dict[str, Any],
    headers: dict[str, str],
    port: int = DEFAULT_PORT,
    timeout: float = 3.0,
) -> tuple[int, dict[str, str], bytes]:
    """Send an HTTP POST probe to /device_request."""
    body_bytes = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        f"http://{ip}:{port}/device_request",
        data=body_bytes,
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, resp_headers, resp.read()


def classify_result(status: int, body: bytes) -> str:
    """Classify probe response into defined outcome buckets."""
    if status == 200:
        if len(body) == 0:
            return "EMPTY_RESPONSE (HTTP 200, 0b)"
        return f"DATA_RETURNED (HTTP 200, {len(body)}b)"
    return f"HTTP_STATUS_{status}"


def build_controlled_experiment_matrix(mac: str, enr: str) -> list[dict[str, Any]]:
    """Build the test matrix isolating headers, schemas, and encryption formats."""
    ts = str(int(time.time() * 1000))
    pids = ["P3", "P1501", "P1502", "P1507"]

    plist_payload = {
        "mac": mac,
        "index": "0",
        "ts": ts,
        "plist": [{"pid": p} for p in pids],
    }
    cids_payload = {
        "mac": mac,
        "index": "0",
        "ts": ts,
        "cids": [0, 1, 2, 3],
    }

    tests: list[dict[str, Any]] = [
        # --- Stage 1: Positive Control ---
        {
            "stage": 1,
            "name": "positive_control_set_status_power_on",
            "request_type": "set_status",
            "inner_payload": {
                "mac": mac,
                "index": "0",
                "ts": ts,
                "plist": [{"pid": "P3", "pvalue": "1"}],
            },
            "pad_mode": "pkcs7",
            "root_response": None,  # omitted by default
            "mesh_node_mac": mac,
            "description": "Baseline working set_status command",
        },
        # --- Stage 2: Header Isolation ---
        # Note on ESP-MDF mlink_httpd.c:
        # If Root-Response == '1' -> httpd_data->type.resp = false (disables response body)
        # If Root-Response == '0' or omitted -> resp = true
        {
            "stage": 2,
            "name": "header_isolation_root_response_omitted_mac_omitted",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": None,
            "description": "Root-Response omitted, Mesh-Node-Mac omitted (resp=true)",
        },
        {
            "stage": 2,
            "name": "header_isolation_root_response_0_mac_set",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "0",
            "mesh_node_mac": mac,
            "description": "Root-Response: 0 (explicit resp=true), Mesh-Node-Mac set",
        },
        {
            "stage": 2,
            "name": "header_isolation_root_response_1_mac_set",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "1",
            "mesh_node_mac": mac,
            "description": "Root-Response: 1 (mlink resp=false check), Mesh-Node-Mac set",
        },
        # --- Stage 3: Encrypted Reads & Protocol Schemas ---
        {
            "stage": 3,
            "name": "encrypted_read_empty_plist_wildcard",
            "request_type": "get_status",
            "inner_payload": {"mac": mac, "index": "0", "ts": ts, "plist": []},
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Encrypted plist=[] wildcard query, Root-Response omitted",
        },
        {
            "stage": 3,
            "name": "encrypted_read_plist_empty_pvalues",
            "request_type": "get_status",
            "inner_payload": {
                "mac": mac,
                "index": "0",
                "ts": ts,
                "plist": [{"pid": p, "pvalue": ""} for p in pids],
            },
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Encrypted plist with empty pvalues, Root-Response omitted",
        },
        {
            "stage": 3,
            "name": "encrypted_read_zero_padded",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "zero",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Null/zero padding (as observed in official Roku app capture)",
        },
        {
            "stage": 3,
            "name": "encrypted_read_cids_schema",
            "request_type": "get_status",
            "inner_payload": cids_payload,
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Documented ESP-MDF CIDs schema encrypted inside characteristics",
        },
        {
            "stage": 3,
            "name": "unencrypted_mlink_cids_schema",
            "request_type": "get_status",
            "inner_payload": None,
            "direct_body": {"request": "get_status", "cids": [0, 1, 2]},
            "pad_mode": "none",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Documented plain ESP-MDF request: {request: get_status, cids: [0,1,2]}",
        },
        {
            "stage": 3,
            "name": "unencrypted_get_device_info",
            "request_type": "get_device_info",
            "inner_payload": None,
            "direct_body": {"request": "get_device_info"},
            "pad_mode": "none",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Documented ESP-MDF get_device_info metadata query",
        },
    ]
    return tests


def start_udp_listener(port: int, stop_event: threading.Event, captured_packets: list[dict[str, Any]]) -> threading.Thread:
    """Listen for unsolicited UDP broadcast packets (e.g. mlink_notice)."""
    def _listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        try:
            sock.bind(("", port))
        except Exception as e:
            print(f"[UDP:{port}] Bind failed: {e}")
            return
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                packet_info = {
                    "time": time.time(),
                    "port": port,
                    "sender": addr,
                    "raw": data,
                }
                captured_packets.append(packet_info)
                print(f"[UDP:{port}] Captured {len(data)} bytes from {addr}: {data[:80]!r}")
            except (socket.timeout, TimeoutError):
                continue
            except Exception as e:
                if not stop_event.is_set():
                    print(f"[UDP:{port}] Error: {e}")
                break
        sock.close()

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    return t


def run_experiment(ip: str, mac: str, enr: str, listen_udp_seconds: float = 0.0) -> list[dict[str, Any]]:
    """Execute the controlled 5-stage experiment."""
    tests = build_controlled_experiment_matrix(mac, enr)
    results: list[dict[str, Any]] = []

    udp_stop = threading.Event()
    udp_packets: list[dict[str, Any]] = []
    threads = []
    if listen_udp_seconds > 0:
        print(f"=== Starting Stage 4: Passive UDP broadcast listener on ports {MLINK_NOTICE_PORT} & {FACTORY_UDP_PORT} ===")
        threads.append(start_udp_listener(MLINK_NOTICE_PORT, udp_stop, udp_packets))
        threads.append(start_udp_listener(FACTORY_UDP_PORT, udp_stop, udp_packets))

    print(f"\n=== Executing Controlled Experiment on {ip} (MAC: {mac}) ===")
    print(f"Total test variants: {len(tests)}\n")

    for idx, t in enumerate(tests, 1):
        name = t["name"]
        stage = t["stage"]
        desc = t["description"]
        print(f"[{idx}/{len(tests)}] [Stage {stage}] {name}")
        print(f"    Intent: {desc}")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Owl/2 CFNetwork/3860.700.1 Darwin/25.6.0",
        }
        if t["root_response"] is not None:
            headers["Root-Response"] = t["root_response"]
        if t["mesh_node_mac"] is not None:
            headers["Mesh-Node-Mac"] = t["mesh_node_mac"]

        if t.get("direct_body") is not None:
            outer_body = t["direct_body"]
        else:
            outer_body = {
                "isSendQueue": 0,
                "request": t["request_type"],
            }
            if t["inner_payload"] is not None:
                outer_body["characteristics"] = encrypt_payload(
                    enr, t["inner_payload"], pad_mode=t["pad_mode"]
                )

        record: dict[str, Any] = {
            "index": idx,
            "stage": stage,
            "name": name,
            "headers": headers,
            "request_body": outer_body,
            "status": None,
            "response_bytes": None,
            "classification": None,
            "decrypted": None,
            "error": None,
        }

        try:
            status, resp_headers, body = send_probe(ip, outer_body, headers)
            classification = classify_result(status, body)
            record["status"] = status
            record["response_bytes"] = len(body)
            record["classification"] = classification

            print(f"    -> Result: {classification}")
            if len(body) > 0:
                print(f"    -> Response Body: {body[:150]!r}")
                try:
                    resp_json = json.loads(body.decode("utf-8"))
                    if "characteristics" in resp_json and isinstance(resp_json["characteristics"], str):
                        decrypted = decrypt_response(enr, resp_json["characteristics"])
                        record["decrypted"] = decrypted
                        print(f"    -> Decrypted Characteristics: {decrypted}")
                except Exception as parse_err:
                    print(f"    -> Decryption/Parse note: {parse_err}")
        except urllib.error.HTTPError as e:
            record["status"] = e.code
            record["classification"] = f"HTTP_ERROR_{e.code}"
            record["error"] = str(e)
            print(f"    -> HTTP Error: {e.code} {e.reason}")
        except urllib.error.URLError as e:
            record["classification"] = "NETWORK_UNREACHABLE"
            record["error"] = str(e.reason)
            print(f"    -> Network error: {e.reason}")
        except Exception as e:
            record["classification"] = "UNEXPECTED_ERROR"
            record["error"] = str(e)
            print(f"    -> Error: {type(e).__name__}: {e}")

        results.append(record)
        time.sleep(1.0)

    if listen_udp_seconds > 0:
        print(f"\nListening for remaining UDP broadcasts ({listen_udp_seconds:.1f}s)...")
        time.sleep(listen_udp_seconds)
        udp_stop.set()
        for th in threads:
            th.join(timeout=1.0)
        print(f"Stage 4 Total UDP broadcast packets captured: {len(udp_packets)}")

    print("\n=== Experiment Summary Table ===")
    print(f"{'Idx':<4} {'Stage':<6} {'Classification':<32} {'Test Name'}")
    print("-" * 75)
    for r in results:
        print(f"{r['index']:<4} {r['stage']:<6} {str(r['classification']):<32} {r['name']}")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigate local state synchronization on Roku/Wyze bulbs.")
    parser.add_argument("ip", help="Bulb LAN IP address")
    parser.add_argument("mac", help="Bulb MAC address (uppercase, no colons)")
    parser.add_argument(
        "--listen-udp",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Also listen for passive UDP broadcasts for N seconds",
    )
    args = parser.parse_args()

    enr = os.environ.get("BULB_ENR", "")
    if len(enr) != 16:
        print("Error: BULB_ENR must be set to the 16-character bulb enr key.", file=sys.stderr)
        return 1

    run_experiment(args.ip, args.mac, enr, listen_udp_seconds=args.listen_udp)
    return 0


if __name__ == "__main__":
    sys.exit(main())

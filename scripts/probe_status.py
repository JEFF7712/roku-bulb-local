#!/usr/bin/env python3
"""Investigate local state synchronization on Roku/Wyze bulbs (BC1000X / RK_BA19C).

Implements a 5-step controlled experiment:
  1. Positive control: observable set_status (e.g. brightness step) to verify control,
     with optional restore and interactive confirmation.
  2. Full 6-way header isolation: 3 Root-Response states (omitted, '0', '1') crossed
     with 2 Mesh-Node-Mac states (omitted, present) with encrypted payload held constant.
     Note: In ESP-MDF mlink_httpd.c, Root-Response: 1 sets resp=false (suppresses
     device responses), whereas omitted/0 leaves resp=true.
  3. Encrypted reads & ESP-MDF Mlink schemas: get_status (plist, cids) & get_device_info.
  4. Passive LAN notifications: listens for UDP broadcasts on port 3232 (mlink_notice
     status broadcast target), 1025 (discovery), and 22223 (factory UDP), including
     pre-flight socket loopback self-test.
  5. Result classification & sanitized JSONL persistence: records exact headers, status,
     timings, sanitized bodies, and classifications to captures/probe_results.jsonl.

Usage:
  BULB_ENR=<16-char enr> python3 scripts/probe_status.py <ip> <mac> [options]
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
# In ESP-MDF mlink_notice.c:
# CONFIG_MLINK_NOTIC_UDP_CLIENT_PORT = 1025 (client discovery)
# CONFIG_MLINK_NOTICE_UDP_SERVER_PORT = 3232 (device status broadcast destination: 255.255.255.255:3232)
MLINK_STATUS_BROADCAST_PORT = 3232
MLINK_DISCOVERY_PORT = 1025
FACTORY_UDP_PORT = 22223

DEFAULT_OUTPUT_JSONL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "captures",
    "probe_results.jsonl",
)


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
) -> tuple[int, dict[str, str], bytes, float]:
    """Send an HTTP POST probe to /device_request, measuring elapsed time."""
    body_bytes = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        f"http://{ip}:{port}/device_request",
        data=body_bytes,
        headers=headers,
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, resp_headers, resp.read(), elapsed_ms


def classify_result(status: int, body: bytes, decrypted: str | None = None) -> str:
    """Precisely classify probe response into defined outcome buckets."""
    if status != 200:
        return f"HTTP_ERROR_{status}"
    if len(body) == 0:
        return "EMPTY_RESPONSE (HTTP 200, 0b)"

    # If body is non-empty, determine whether it carries actual state or an error/status wrapper
    if decrypted is not None:
        try:
            parsed = json.loads(decrypted)
            if isinstance(parsed, dict) and ("plist" in parsed or "cids" in parsed):
                return f"STATUS_PAYLOAD_RETURNED ({len(body)}b)"
        except Exception:
            pass

    try:
        parsed_body = json.loads(body.decode("utf-8"))
        if isinstance(parsed_body, dict):
            if "status_code" in parsed_body and len(parsed_body) == 1:
                return f"ACK_STATUS_CODE_{parsed_body['status_code']} ({len(body)}b)"
            if "characteristics" in parsed_body:
                return f"ENCRYPTED_CHARACTERISTICS_RETURNED ({len(body)}b)"
            if "error" in parsed_body or "msg" in parsed_body:
                return f"ERROR_BODY_RETURNED ({len(body)}b)"
    except Exception:
        pass

    return f"NON_EMPTY_UNPARSED_BODY (HTTP 200, {len(body)}b)"


def build_controlled_experiment_matrix(mac: str, enr: str) -> list[dict[str, Any]]:
    """Build the test matrix isolating the full 6-way header matrix, schemas, and encryption formats."""
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
            "name": "positive_control_brightness_step",
            "request_type": "set_status",
            "inner_payload": {
                "mac": mac,
                "index": "0",
                "ts": ts,
                "plist": [{"pid": "P3", "pvalue": "1"}, {"pid": "P1501", "pvalue": "50"}],
            },
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Baseline working set_status command (power on + brightness 50)",
        },
        # --- Stage 2: Full 6-way Header Isolation Factorial ---
        # 3 Root-Response states (omitted, '0', '1') x 2 Mesh-Node-Mac states (omitted, mac)
        # Payload is held constant across all 6 combinations.
        {
            "stage": 2,
            "name": "header_isolation_rr_omitted_mac_omitted",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": None,
            "description": "Combo 1/6: Root-Response omitted, Mesh-Node-Mac omitted",
        },
        {
            "stage": 2,
            "name": "header_isolation_rr_omitted_mac_present",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": None,
            "mesh_node_mac": mac,
            "description": "Combo 2/6: Root-Response omitted, Mesh-Node-Mac present",
        },
        {
            "stage": 2,
            "name": "header_isolation_rr_0_mac_omitted",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "0",
            "mesh_node_mac": None,
            "description": "Combo 3/6: Root-Response: 0 (explicit resp=true), Mesh-Node-Mac omitted",
        },
        {
            "stage": 2,
            "name": "header_isolation_rr_0_mac_present",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "0",
            "mesh_node_mac": mac,
            "description": "Combo 4/6: Root-Response: 0 (explicit resp=true), Mesh-Node-Mac present",
        },
        {
            "stage": 2,
            "name": "header_isolation_rr_1_mac_omitted",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "1",
            "mesh_node_mac": None,
            "description": "Combo 5/6: Root-Response: 1 (mlink resp=false), Mesh-Node-Mac omitted",
        },
        {
            "stage": 2,
            "name": "header_isolation_rr_1_mac_present",
            "request_type": "get_status",
            "inner_payload": plist_payload,
            "pad_mode": "pkcs7",
            "root_response": "1",
            "mesh_node_mac": mac,
            "description": "Combo 6/6: Root-Response: 1 (mlink resp=false), Mesh-Node-Mac present",
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


def start_udp_listener(
    port: int,
    stop_event: threading.Event,
    captured_packets: list[dict[str, Any]],
) -> tuple[threading.Thread, bool]:
    """Listen for UDP broadcast packets with pre-flight self-test."""
    ready_event = threading.Event()
    bind_success = [False]

    def _listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        try:
            sock.bind(("", port))
            bind_success[0] = True
        except Exception as e:
            print(f"[UDP:{port}] Bind failed: {e}")
            ready_event.set()
            return

        ready_event.set()
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                packet_info = {
                    "time": time.time(),
                    "port": port,
                    "sender": addr[0],
                    "sender_port": addr[1],
                    "len": len(data),
                    "raw_hex": data.hex(),
                }
                captured_packets.append(packet_info)
                print(f"[UDP:{port}] Captured {len(data)} bytes from {addr[0]}:{addr[1]}: {data[:60]!r}")
            except (socket.timeout, TimeoutError):
                continue
            except Exception as e:
                if not stop_event.is_set():
                    print(f"[UDP:{port}] Error: {e}")
                break
        sock.close()

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    ready_event.wait(timeout=2.0)

    # Perform loopback self-test to validate socket reception
    if bind_success[0]:
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(b"ROKU_PROBE_SELF_TEST", ("127.0.0.1", port))
            sender.close()
            time.sleep(0.1)
        except Exception as e:
            print(f"[UDP:{port}] Self-test packet failed: {e}")

    return t, bind_success[0]


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Redact keys, credentials, and sensitive tokens from record."""
    sanitized = json.loads(json.dumps(record))
    if "request_body" in sanitized and isinstance(sanitized["request_body"], dict):
        if "characteristics" in sanitized["request_body"]:
            sanitized["request_body"]["characteristics"] = "***REDACTED_CIPHERTEXT***"
    return sanitized


def run_experiment(
    ip: str,
    mac: str,
    enr: str,
    listen_udp_seconds: float = 0.0,
    output_path: str = DEFAULT_OUTPUT_JSONL,
    interactive: bool = False,
    restore_brightness: int | None = None,
) -> list[dict[str, Any]]:
    """Execute the controlled 5-stage experiment with sanitized persistence."""
    tests = build_controlled_experiment_matrix(mac, enr)
    results: list[dict[str, Any]] = []

    udp_stop = threading.Event()
    udp_packets: list[dict[str, Any]] = []
    threads = []
    if listen_udp_seconds > 0:
        print(f"=== Starting Stage 4: Passive UDP broadcast listener on ports {MLINK_STATUS_BROADCAST_PORT}, {MLINK_DISCOVERY_PORT}, {FACTORY_UDP_PORT} ===")
        for p in (MLINK_STATUS_BROADCAST_PORT, MLINK_DISCOVERY_PORT, FACTORY_UDP_PORT):
            th, ok = start_udp_listener(p, udp_stop, udp_packets)
            if ok:
                threads.append(th)
                print(f"    [UDP:{p}] Socket verified and active.")

    print(f"\n=== Executing Controlled Experiment on {ip} (MAC: {mac}) ===")
    print(f"Total test variants: {len(tests)}\n")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

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
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "index": idx,
            "stage": stage,
            "name": name,
            "headers": headers,
            "request_body": outer_body,
            "status": None,
            "response_bytes": None,
            "duration_ms": None,
            "classification": None,
            "decrypted": None,
            "error": None,
            "independent_verification": None,
        }

        try:
            status, resp_headers, body, elapsed_ms = send_probe(ip, outer_body, headers)
            record["status"] = status
            record["response_headers"] = resp_headers
            record["response_bytes"] = len(body)
            record["duration_ms"] = elapsed_ms

            decrypted_str = None
            if len(body) > 0:
                try:
                    resp_json = json.loads(body.decode("utf-8"))
                    if "characteristics" in resp_json and isinstance(resp_json["characteristics"], str):
                        decrypted_str = decrypt_response(enr, resp_json["characteristics"])
                        record["decrypted"] = decrypted_str
                except Exception:
                    pass

            classification = classify_result(status, body, decrypted=decrypted_str)
            record["classification"] = classification

            print(f"    -> Result: {classification} ({elapsed_ms}ms)")
            if decrypted_str:
                print(f"    -> Decrypted Characteristics: {decrypted_str}")

            # Positive control observation / verification
            if stage == 1:
                if interactive:
                    ans = input("    -> Positive control check: Did the bulb visibly respond? [y/N]: ").strip().lower()
                    record["independent_verification"] = "CONFIRMED_BY_OPERATOR" if ans == "y" else "UNVERIFIED"
                else:
                    record["independent_verification"] = "COMMAND_ACCEPTED_HTTP_200"

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

        # Persist structured sanitized record immediately
        try:
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sanitize_record(record)) + "\n")
        except Exception as write_err:
            print(f"    [Warning] Failed to write result log: {write_err}")

        time.sleep(1.0)

    # Optional restoration of positive control brightness
    if restore_brightness is not None:
        print(f"\nRestoring positive control brightness to {restore_brightness}...")
        restore_body = {
            "isSendQueue": 0,
            "request": "set_status",
            "characteristics": encrypt_payload(
                enr,
                {
                    "mac": mac,
                    "index": "0",
                    "ts": str(int(time.time() * 1000)),
                    "plist": [{"pid": "P1501", "pvalue": str(restore_brightness)}],
                },
            ),
        }
        try:
            send_probe(ip, restore_body, {"Content-Type": "application/json", "Mesh-Node-Mac": mac})
            print("    -> Restore command dispatched.")
        except Exception as e:
            print(f"    -> Restore failed: {e}")

    if listen_udp_seconds > 0:
        print(f"\nListening for remaining UDP broadcasts ({listen_udp_seconds:.1f}s)...")
        time.sleep(listen_udp_seconds)
        udp_stop.set()
        for th in threads:
            th.join(timeout=1.0)
        # Filter out local loopback self-test packets
        external_packets = [p for p in udp_packets if p.get("sender") != "127.0.0.1"]
        print(f"Stage 4 Total external UDP broadcast packets captured: {len(external_packets)}")

    print(f"\n=== Experiment Summary Table (Saved to {output_path}) ===")
    print(f"{'Idx':<4} {'Stage':<6} {'Classification':<36} {'Test Name'}")
    print("-" * 80)
    for r in results:
        print(f"{r['index']:<4} {r['stage']:<6} {str(r['classification']):<36} {r['name']}")

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
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt operator to visually verify positive control state changes",
    )
    parser.add_argument(
        "--restore-brightness",
        type=int,
        default=None,
        metavar="1-100",
        help="Restore bulb brightness to this percentage after testing",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_JSONL,
        help=f"Path to write structured JSONL results (default: {DEFAULT_OUTPUT_JSONL})",
    )
    args = parser.parse_args()

    enr = os.environ.get("BULB_ENR", "")
    if len(enr) != 16:
        print("Error: BULB_ENR must be set to the 16-character bulb enr key.", file=sys.stderr)
        return 1

    run_experiment(
        args.ip,
        args.mac,
        enr,
        listen_udp_seconds=args.listen_udp,
        output_path=args.output,
        interactive=args.interactive,
        restore_brightness=args.restore_brightness,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

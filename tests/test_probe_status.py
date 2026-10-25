from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from probe_status import (
    build_controlled_experiment_matrix,
    classify_result,
    decrypt_response,
    encrypt_payload,
    run_experiment,
    sanitize_record,
    send_probe,
    start_udp_listener,
)

DUMMY_MAC = "AA1122334455"
DUMMY_ENR = "SYNTHETICTEST001"


def test_encrypt_decrypt_roundtrip_pkcs7():
    payload = {"mac": DUMMY_MAC, "plist": [{"pid": "P3", "pvalue": "1"}]}
    enc = encrypt_payload(DUMMY_ENR, payload, pad_mode="pkcs7")
    dec_str = decrypt_response(DUMMY_ENR, enc)
    dec_obj = json.loads(dec_str)
    assert dec_obj == payload


def test_encrypt_decrypt_roundtrip_zero_pad():
    payload = {"mac": DUMMY_MAC, "plist": [{"pid": "P3", "pvalue": "0"}]}
    enc = encrypt_payload(DUMMY_ENR, payload, pad_mode="zero")
    dec_str = decrypt_response(DUMMY_ENR, enc)
    dec_obj = json.loads(dec_str)
    assert dec_obj == payload


def test_build_controlled_experiment_matrix_full_header_isolation():
    matrix = build_controlled_experiment_matrix(DUMMY_MAC, DUMMY_ENR)
    stage2_tests = [t for t in matrix if t["stage"] == 2]

    # Full 6-way factorial: 3 Root-Response x 2 Mesh-Node-Mac
    assert len(stage2_tests) == 6

    combos = {(t["root_response"], t["mesh_node_mac"]) for t in stage2_tests}
    expected_combos = {
        (None, None),
        (None, DUMMY_MAC),
        ("0", None),
        ("0", DUMMY_MAC),
        ("1", None),
        ("1", DUMMY_MAC),
    }
    assert combos == expected_combos

    # Verify payload is held strictly constant across all 6 combinations
    inner_payloads = [t["inner_payload"] for t in stage2_tests]
    assert all(p == inner_payloads[0] for p in inner_payloads)


def test_classify_result_precision():
    # Empty 200
    assert "EMPTY_RESPONSE" in classify_result(200, b"")

    # Decrypted characteristics carrying state
    decrypted_state = json.dumps({"plist": [{"pid": "P3", "pvalue": "1"}]})
    assert "STATUS_PAYLOAD_RETURNED" in classify_result(200, b'{"status_code":0}', decrypted=decrypted_state)

    # Bare ACK status code
    assert "ACK_STATUS_CODE_0" in classify_result(200, b'{"status_code":0}')

    # Encrypted characteristics wrapper returned but not decrypted
    assert "ENCRYPTED_CHARACTERISTICS_RETURNED" in classify_result(200, b'{"characteristics":"abc"}')

    # Non-200 HTTP status
    assert "HTTP_ERROR_404" in classify_result(404, b"Not Found")

    # Unparsed arbitrary body
    assert "NON_EMPTY_UNPARSED_BODY" in classify_result(200, b"raw string payload")


def test_sanitize_record_redacts_secrets():
    record = {
        "test_name": "test_probe",
        "request_body": {
            "request": "set_status",
            "characteristics": "SECRET_CIPHERTEXT_12345",
        },
    }
    sanitized = sanitize_record(record)
    assert sanitized["request_body"]["characteristics"] == "***REDACTED_CIPHERTEXT***"


@patch("probe_status.urllib.request.urlopen")
def test_send_probe(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "text/html", "Transfer-Encoding": "chunked"}
    mock_resp.read.return_value = b""
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    status, headers, body, elapsed = send_probe("127.0.0.1", {"request": "get_status"}, {})
    assert status == 200
    assert headers["content-type"] == "text/html"
    assert body == b""
    assert elapsed >= 0.0


@patch("probe_status.send_probe")
@patch("probe_status.time.sleep")
def test_run_experiment_persists_sanitized_results(mock_sleep, mock_send_probe, tmp_path):
    output_file = str(tmp_path / "test_results.jsonl")
    returned_characteristics = encrypt_payload(DUMMY_ENR, {"plist": [{"pid": "P3", "pvalue": "1"}]})
    resp_body = json.dumps({"status_code": 0, "characteristics": returned_characteristics}).encode()
    mock_send_probe.return_value = (200, {"content-type": "application/json"}, resp_body, 12.5)

    results = run_experiment(
        "10.0.20.117",
        DUMMY_MAC,
        DUMMY_ENR,
        listen_udp_seconds=0.1,
        output_path=output_file,
        restore_brightness=45,
        restore_power="off",
    )
    assert len(results) >= 12
    assert os.path.exists(output_file)

    with open(output_file) as f:
        lines = [json.loads(line) for line in f]
    # Check that probe lines plus the udp_capture_summary record are present
    assert len(lines) >= len(results)
    probe_entries = [e for e in lines if "request_body" in e]
    for entry in probe_entries:
        if "characteristics" in entry["request_body"]:
            assert entry["request_body"]["characteristics"] == "***REDACTED_CIPHERTEXT***"
    udp_entries = [e for e in lines if e.get("record_type") == "udp_capture_summary"]
    assert len(udp_entries) == 1

    # Verify that the restore command was dispatched (with both P3=0 and P1501=45)
    restore_call = mock_send_probe.call_args_list[-1]
    restore_body = restore_call[0][1]
    assert restore_body["request"] == "set_status"
    decrypted_restore = decrypt_response(DUMMY_ENR, restore_body["characteristics"])
    restore_json = json.loads(decrypted_restore)
    assert restore_json["plist"] == [{"pid": "P3", "pvalue": "0"}, {"pid": "P1501", "pvalue": "45"}]


def test_udp_listener_loopback_self_test():
    import threading
    stop_event = threading.Event()
    packets = []
    # Test on a high unprivileged ephemeral port
    th, ok = start_udp_listener(14232, stop_event, packets)
    assert ok
    stop_event.set()
    th.join(timeout=1.0)
    # Self-test should have captured the test datagram
    assert any(b"ROKU_PROBE_SELF_TEST" in bytes.fromhex(p["raw_hex"]) for p in packets)

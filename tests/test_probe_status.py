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
    send_probe,
)


def test_encrypt_decrypt_roundtrip_pkcs7():
    enr = "JgS72CmlwDrx9F9D"
    payload = {"mac": "7C67AB0A83AB", "plist": [{"pid": "P3", "pvalue": "1"}]}
    enc = encrypt_payload(enr, payload, pad_mode="pkcs7")
    dec_str = decrypt_response(enr, enc)
    dec_obj = json.loads(dec_str)
    assert dec_obj == payload


def test_encrypt_decrypt_roundtrip_zero_pad():
    enr = "JgS72CmlwDrx9F9D"
    payload = {"mac": "7C67AB0A83AB", "plist": [{"pid": "P3", "pvalue": "0"}]}
    enc = encrypt_payload(enr, payload, pad_mode="zero")
    dec_str = decrypt_response(enr, enc)
    dec_obj = json.loads(dec_str)
    assert dec_obj == payload


def test_build_controlled_experiment_matrix():
    matrix = build_controlled_experiment_matrix("7C67AB0A83AB", "JgS72CmlwDrx9F9D")
    stages = {t["stage"] for t in matrix}
    assert stages == {1, 2, 3}
    names = [t["name"] for t in matrix]
    assert "positive_control_set_status_power_on" in names
    assert "header_isolation_root_response_omitted_mac_omitted" in names
    assert "header_isolation_root_response_0_mac_set" in names
    assert "header_isolation_root_response_1_mac_set" in names
    assert "unencrypted_mlink_cids_schema" in names
    assert "unencrypted_get_device_info" in names


def test_classify_result():
    assert "EMPTY_RESPONSE" in classify_result(200, b"")
    assert "DATA_RETURNED" in classify_result(200, b'{"status_code":0}')
    assert "HTTP_STATUS_404" in classify_result(404, b"Not Found")


@patch("probe_status.urllib.request.urlopen")
def test_send_probe(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "text/html", "Transfer-Encoding": "chunked"}
    mock_resp.read.return_value = b""
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    status, headers, body = send_probe("127.0.0.1", {"request": "get_status"}, {})
    assert status == 200
    assert headers["content-type"] == "text/html"
    assert body == b""


@patch("probe_status.send_probe")
@patch("probe_status.time.sleep")
def test_run_experiment_decodes_characteristics(mock_sleep, mock_send_probe):
    enr = "JgS72CmlwDrx9F9D"
    returned_characteristics = encrypt_payload(enr, {"plist": [{"pid": "P3", "pvalue": "1"}]})
    resp_body = json.dumps({"status_code": 0, "characteristics": returned_characteristics}).encode()
    mock_send_probe.return_value = (200, {"content-type": "application/json"}, resp_body)

    results = run_experiment("10.0.20.117", "7C67AB0A83AB", enr, listen_udp_seconds=0.0)
    assert len(results) >= 8
    # Ensure decrypted payload was extracted
    assert any(r["decrypted"] is not None for r in results)

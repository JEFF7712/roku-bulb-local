"""
mitmproxy capture addon for the Roku Smart Home (Wyze) app.

Logs every HTTP(S) request/response pair as one JSON object per line to
capture/roku_api.jsonl, and prints a concise live line to stdout so we can
confirm traffic is flowing. Binary/asset bodies are skipped; text bodies are
truncated. We capture ALL hosts (not just *.wyze/*.roku) so we don't miss the
real control endpoint, then filter when reading.

Run:  mitmdump.exe -s capture_addon.py --listen-port 8080
"""

import json
import os
import time

from mitmproxy import http

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "captures", "roku_api.jsonl")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# Content types whose bodies aren't useful to log (assets, media, code).
SKIP_CT = (
    "image/", "video/", "audio/", "font/",
    "application/octet-stream", "application/wasm",
    "text/css", "application/javascript", "text/javascript",
)
MAXLEN = 8000  # truncate text bodies to this many chars


def _body_text(message) -> str:
    ct = message.headers.get("content-type", "").lower()
    raw_len = len(message.raw_content or b"")
    if any(ct.startswith(s) for s in SKIP_CT):
        return f"<{ct or 'binary'} {raw_len}B>"
    try:
        t = message.get_text(strict=False)
    except Exception:
        return f"<undecodable {raw_len}B>"
    if not t:
        return ""
    if len(t) > MAXLEN:
        return t[:MAXLEN] + f"...<+{len(t) - MAXLEN} more>"
    return t


def response(flow: http.HTTPFlow) -> None:
    req = flow.request
    resp = flow.response
    rec = {
        "ts": time.strftime("%H:%M:%S"),
        "client": flow.client_conn.peername[0] if flow.client_conn.peername else "",
        "method": req.method,
        "scheme": req.scheme,
        "host": req.pretty_host,
        "port": req.port,
        "path": req.path,
        "req_headers": dict(req.headers),
        "req_body": _body_text(req),
        "status": resp.status_code,
        "resp_headers": dict(resp.headers),
        "resp_body": _body_text(resp),
    }
    try:
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # never let logging crash the proxy
        print(f"[capture-addon] write error: {e}")

    bare_path = req.path.split("?", 1)[0]
    print(f"[{rec['client']}] {req.method} {rec['host']}{bare_path} -> {resp.status_code}")

# Local HTTP API on BC1000P2R (found 2026-09-10)

Bulb `192.168.1.50` (BC1000P2R, fw 1.1.1.15) exposes a working HTTP server on **TCP 88**.
This contradicts the earlier RK_BA19C report of no listening ports. That scan may have
covered a different model or firmware, or missed port 88.

## Confirmed behavior (read-only probes)

- `GET /` returns `404 This URI does not exist` (server is HTTP, not raw socket).
- `GET /device_request` returns `405 Request method for this URI is not handled by server`.
  The URI exists and requires POST. This matches the historic Wyze local endpoint.
- `POST /device_request` with empty body or `{}` returns `200` with empty chunked body.
- `POST {"request":"get_status","isSendQueue":0}` returns `200` with empty body.
  Queries appear to require the encrypted `characteristics` field too.

## Status: WORKING (verified 2026-09-10)

`scripts/local_set.py` sent `P1501=50` to Desk Lamp via port 88, cloud
read-back confirmed `P1501 50` with fresh ts, then restored to 45.
Retail model per Roku cloud is `BC1000X`, provider key `RK_BA19C`,
type `MeshLight`. enr values live only in `captures/roku_api.jsonl`
(gitignored, never commit). Pass via `BULB_ENR` env.

## Crash warning

`POST` with `characteristics` as a nested JSON object (instead of a string)
kills the port 88 server: connection reset, then connection refused for ~20s.
The bulb keeps responding to ping and the server recovers on its own
(watchdog or reboot). Lesson: only send spec-shaped bodies where
`characteristics` is a string. Do not fuzz this endpoint.

## Protocol (from Wyze forum 206479 plus dgmltn/wyze-python `app.py`)

```text
POST http://<bulb>:88/device_request
{"request":"set_status","isSendQueue":0,"characteristics":"<base64>"}
```

Plaintext before encryption (compact JSON, no spaces):

```json
{"mac":"7C67ABAABBCC","index":"0","ts":"<epoch-ms>","plist":[{"pid":"P3","pvalue":"1"}]}
```

- Encryption: AES-CBC, key = bulb `enr`, IV = bulb `enr`, PKCS7 pad, base64 output.
- Pids: P3 power 1/0, P1501 brightness 1-100, P1502 white temp in K, P1507 RGB hex.
- `index` is `"0"` in dgmltn code, `"1"` in the forum post. Try `"0"` first.

## Missing piece: `enr`

`enr` is a per-device secret returned by the Wyze cloud API (`client.bulbs.info().enr`
in wyze-sdk). Our bulb is bound to the Roku app, not a Wyze account, so a plain
Wyze login will not list it. Retrieval path:

1. MITM the Roku Smart Home app per Metrix187 (`mitmdump` plus `capture_addon.py`)
   to capture the Wyze `access_token` (and any device-info responses, which may
   already contain `enr`).
2. Call the Wyze device-info endpoint with that token plus Roku app headers
   (`app_ver com.roku.ios.rokuhome___3.6.0.2`) and read `enr` for your bulb's MAC.
3. Encrypt locally with `uv run` plus `pycryptodome`, POST to port 88, verify
   with a no-op read or a single brightness set while watching the bulb.

No `hap upgrade` or factory cycling until the local path is exhausted. It gives
LAN control with stock firmware and zero flash risk.

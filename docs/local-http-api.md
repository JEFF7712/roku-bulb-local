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

## State synchronization & `get_status` investigation

### Background & Architecture

In testing and network captures (`captures/roku_api.jsonl`), local state queries (`get_status`) have historically returned empty responses (`HTTP/1.1 200 OK` with 0-byte chunked body). Analyzing the protocol origins and app traffic reveals why:

1. **ESP-MDF Mlink Foundation**: The port 88 HTTP server is derived from Espressif's ESP-MDF (Mesh Development Framework) `mlink_httpd` module, adapted by Wyze/Roku with an AES-128-CBC encryption envelope.
2. **App Traffic Pattern**: The official Roku Smart Home App treats port 88 exclusively as a **write-only / fire-and-forget control fast-path** (`request: "set_status"`). The app **never** sends `get_status` requests to port 88 over the local network.
3. **Cloud-Tethered State**: State updates in the official app are handled entirely through cloud polling (`POST https://api.wyzeiot.com:443/app/v2/device_list/get_property_list` every 30 seconds) and push notifications via WebSocket connections (`aspen-sockets.production.aspen.rokuapi.net:443/v1/socket`). The bulb firmware itself pushes its state upstream to the cloud via its background MQTT connection upon physical or remote state changes.

### Probing Encrypted `get_status`

Initial unencrypted probes like `POST {"request":"get_status","isSendQueue":0}` returned empty bodies because `/device_request` discards malformed or empty payloads without an error response (returning 200 with 0 bytes).

Crucially, regarding ESP-MDF Mlink headers and ports:
- `Mesh-Node-Num` is a server enumeration header, not a mandatory request header.
- In `mlink_httpd.c`, `Root-Response: 1` sets `httpd_data->type.resp = false`, which **suppresses** standard device response payloads. Omitting the header or passing `Root-Response: 0` keeps `resp = true`.
- In `mlink_notice.c`, status broadcasts are dispatched to **UDP port 3232** (`CONFIG_MLINK_NOTICE_UDP_SERVER_PORT`), while **UDP port 1025** is the device listener for discovery requests.

To systematically probe whether the bulb firmware's port 88 implementation supports returning encrypted state, use `scripts/probe_status.py`:

```bash
BULB_ENR=<enr> python3 scripts/probe_status.py <ip> <mac> \
  --listen-udp 10 \
  --interactive \
  --restore-power off \
  --restore-brightness 45
```

This script executes a 5-step controlled experiment:
1. **Positive control**: Executes an observable brightness step (`P3=1, P1501=50`), measures exact latency, verifies HTTP 200, optionally prompts for visual operator confirmation, and restores initial power/brightness states (`--restore-power`, `--restore-brightness`) when finished.
2. **Full 6-way header isolation**: Evaluates all combinations of `Root-Response` (omitted, `"0"`, `"1"`) x `Mesh-Node-Mac` (omitted, `<mac>`) while holding payload constant.
3. **Encrypted reads & schemas**: Evaluates encrypted `plist`, wildcard `plist: []`, ESP-MDF CID schemas `{"request":"get_status","cids":[0,1,2]}`, and `get_device_info`.
4. **Passive LAN event listener & capture**: Pre-flight loopback validates and listens on UDP port 3232 (status broadcasts), 1025 (discovery), and 22223.
5. **Sanitized structured logging**: Saves sanitized results (redacting keys/ciphertext) with precise classifications (`EMPTY_RESPONSE`, `STATUS_PAYLOAD_RETURNED`, `ACK_STATUS_CODE`, `HTTP_ERROR`, `TIMEOUT`) to `captures/probe_results.jsonl`.

### Auxiliary packet capture on bulb VLAN

For full Layer 2 visibility (including capturing packets emitted by the bulb when toggled via the official Roku app), run `tcpdump` on the same subnet:

```bash
sudo tcpdump -ni <iface> -s 0 -w captures/roku-probe.pcap 'udp and (port 1025 or port 3232 or port 22223)'
```




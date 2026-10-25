# roku-bulb-local

Local LAN control for Roku smart bulbs (retail `BC1000P2R`, provider key
`RK_BA19C`, rebranded Wyze) with stock firmware. No cloud, no flashing.

Status: WORKING. `scripts/local_set.py` sends one-off commands and
`scripts/bridge.py` exposes bulbs to Home Assistant over MQTT with
auto-discovery. A Roku Light Strip (`RK_LS`) speaks the same protocol.

## How it works

These bulbs run an HTTP server on **TCP port 88** with a Wyze-compatible
`POST /device_request` endpoint. Commands are AES-CBC encrypted with a
per-device 16-char secret (`enr`, key = IV), PKCS7 padded, base64 encoded.
Pids: `P3` power (1/0), `P1501` brightness (1-100), `P1502` white temp in K
(1800-6500), `P1507` RGB hex (`FF0000`). Details in
`docs/local-http-api.md`.

The catch is `enr`: it is only issued by the Wyze cloud backing the Roku
Smart Home app, so you capture it once per bulb and then control the bulb
over LAN indefinitely.

## Setup

1. Put the bulb on your LAN and find its IP (DHCP lease, `nmap -p 88 --open <subnet>`).
2. Capture `enr` once per bulb by proxying the Roku Smart Home app through
   mitmproxy on your computer:
   1. Join the phone and the computer to the same Wi-Fi. Start the capture:
      `mitmdump -s scripts/capture_addon.py --listen-port 8080`.
   2. On the phone, set a manual HTTP proxy to `<computer-IP>:8080`
      (iOS: Wi-Fi network details, Configure Proxy; Android: Wi-Fi network,
      edit, advanced Proxy Manual).
   3. Install and trust the interception certificate: on the phone visit
      `http://mitm.it`, download the profile, then enable it. iOS: install
      under Settings, General, VPN and Device Management, then flip full
      trust under Settings, General, About, Certificate Trust Settings.
      Android: install as a CA certificate under Settings, Security,
      Encryption and credentials. Revert the proxy setting when done.
   4. Open the Roku Smart Home app and pull to refresh the device list
      (toggling the bulb also works). Confirm traffic in the mitmdump
      output, then stop it with Ctrl-C.
   5. Find `enr` in `captures/roku_api.jsonl`: look at the
      `POST api.wyzeiot.com/app/v2/home_page/get_object_list` response,
      in `device_list`, for the entry whose `mac` equals your bulb's MAC
      without colons. Its `enr` is a 16-character string. Shortcut:
      ```bash
      python3 -c "
      import json
      want = 'YOUR_MAC_WITHOUT_COLONS'.upper()
      for line in open('captures/roku_api.jsonl'):
          try: r = json.loads(line)
          except ValueError: continue
          try: body = json.loads(r.get('resp_body') or 'null')
          except ValueError: continue
          data = body.get('data') if isinstance(body, dict) else None
          devs = data.get('device_list', []) if isinstance(data, dict) else (data or [])
          for d in devs:
              if isinstance(d, dict) and d.get('mac') == want: print(d.get('nickname'), d.get('enr'))
      "
      ```
   Privacy note: the addon logs every host passing through the proxy,
   including other apps, with request/response headers and bodies (32 of
   79 lines in one lab capture carried auth tokens). `captures/` is
   gitignored for this reason. Keep it local, never post the file.
3. Send a test command:

```bash
uv venv .venv && uv pip install -r requirements.txt
BULB_ENR=<16-char enr> .venv/bin/python scripts/local_set.py <ip> <mac-no-colons> P1501 50
```

Do not send `characteristics` as a nested JSON object instead of a string:
it crashes the bulb's port 88 server for ~20s (it recovers on its own).
Only send spec-shaped bodies.

## Home Assistant

```bash
cp scripts/bulbs.example.yaml scripts/bulbs.yaml  # gitignored, fill enr from capture
chmod 600 scripts/bulbs.yaml
MQTT_HOST=<broker> MQTT_USER=<user> MQTT_PASS=<pass> \
  .venv/bin/python scripts/bridge.py --config scripts/bulbs.yaml
```

HA discovers each bulb automatically. See `docs/ha-bridge.md` for full-time
deployment, and `scripts/bulbs.example.yaml` for the config format.

## Compatibility

Tested against stock firmware, no flashing. Values below come from the
`get_object_list` capture (`product_model`, `model`, `firmware_ver`).

| Device | Retail box | Cloud model | Provider key | Type | Tested firmware |
|---|---|---|---|---|---|
| Roku color A19 bulb (x2 units) | BC1000P2R | BC1000X | RK_BA19C | MeshLight | 1.1.1.15 |
| Roku Light Strip | (box model unrecorded) | LS1016X | RK_LS | LightStrip | 1.2.1.13 |

Both speak the same `:88` protocol and pids. Other models or firmware may
work but are untested; a bulb without a port 88 server needs the
factory-mode path in `docs/factory-mode-detection.md`.

## Layout

- `scripts/local_set.py`: one-off encrypted command. Secret via `BULB_ENR` env.
- `scripts/bridge.py`: MQTT bridge with HA discovery. Config in `bulbs.yaml` (gitignored).
- `scripts/capture_addon.py`: mitmproxy addon that logs app traffic to find `enr`.
- `scripts/detect_factory_mode.py`: passive UDP 22223 listener for factory-mode research.
- `scripts/lab-scan.sh`: baseline nmap plus tcpdump wrappers.
- `docs/local-http-api.md`: protocol reference and crash warning.
- `docs/ha-bridge.md`: bridge runbook.
- `docs/bulb-inventory.md`: template for recording your bulbs (example values only).
- `docs/factory-mode-detection.md`, `docs/wyze-reference.md`: factory-flash research notes.
- `tests/test_bridge.py`: bridge unit tests (`uv run --with pytest` or `.venv/bin/python -m pytest tests/`).

## License

MIT. See `LICENSE`.

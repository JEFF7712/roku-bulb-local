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
2. Capture `enr` once per bulb by MITMing the Roku Smart Home app:
   `mitmdump -s scripts/capture_addon.py --listen-port 8080`, then open the
   app and look at `captures/roku_api.jsonl` for the device-info response
   containing `enr` for your bulb's MAC. (`captures/` is gitignored.)
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

## Research background

This started as a wireless-conversion project: Roku RK_BA19C as a rebranded
Wyze color A19, possibly sharing the WLPA19CV2 factory-test mechanism (UDP
port 22223 after ~17 power cycles, hijack AP, custom loader, ESPHome). That
path is shelved: the stock firmware already accepts local commands, which
gives fully local control with zero flash risk. The factory-mode notes stay
for anyone whose bulb or firmware lacks port 88.

Reference: `nickdaria/wyze-bulb-color-pwned` (Wyze WLPA19CV2 loader plus
ESPHome config). Key constants are summarized in `docs/wyze-reference.md`.

## Safety

Do not probe or disassemble an energized bulb. Mains voltage on PCB. Network
and wireless work only.

## License

MIT. See `LICENSE`.

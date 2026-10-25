# HA bridge (`scripts/bridge.py`)

MQTT bridge with Home Assistant discovery. Verified end to end against a
BC1000P2R bulb through a local broker: MQTT set → encrypted local
command → bulb, state plus retained discovery published.

## Run

```bash
cp scripts/bulbs.example.yaml scripts/bulbs.yaml  # gitignored, fill enr from capture
chmod 600 scripts/bulbs.yaml
MQTT_HOST=<broker> MQTT_PORT=1883 MQTT_USER=<user> MQTT_PASS=<pass> \
  python3 scripts/bridge.py --config scripts/bulbs.yaml
```

Needs `pyyaml`, `paho-mqtt`, `pycryptodome` (see `requirements.txt`):

```bash
uv venv .venv && uv pip install -r requirements.txt
```

HA picks up each bulb automatically via discovery (`homeassistant/light/...`).
No HA config changes. Entities support on/off, brightness, color temp
(1800-6500 K), RGB. Optimistic mode: app or physical changes do not sync
back (local `get_status` returns nothing).

## Running it full time

The bridge needs to stay up alongside your MQTT broker. On any always-on
Linux host:

1. Create a dedicated broker user for the bridge with read/write access to
   `homeassistant/#` and `roku/#` (topic prefix is configurable via
   `--prefix`).
2. Deploy `bulbs.yaml` (mode 600) next to the checkout.
3. Run the bridge under your process supervisor. A minimal systemd user unit:

```ini
[Unit]
Description=Roku bulb MQTT bridge
After=network-online.target

[Service]
ExecStart=%h/roku-bulb-local/.venv/bin/python %h/roku-bulb-local/scripts/bridge.py --config %h/roku-bulb-local/scripts/bulbs.yaml
Environment=MQTT_HOST=<broker> MQTT_USER=<user> MQTT_PASS=<pass>
Restart=on-failure

[Install]
WantedBy=default.target
```

Check the logs for one `discovery + subscribe` line per bulb.

Tokens captured from the app expire. The bridge itself is fully
local after discovery; only verification reads use cloud.

## Adding a bulb later

Append `{"name", "mac", "ip", "enr"}` to `bulbs.yaml` and restart the
bridge. Verified working for a second device class: a Roku Light Strip
(`RK_LS`) speaks the same `:88` protocol and pids as the `RK_BA19C` bulbs.

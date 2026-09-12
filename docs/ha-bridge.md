# HA bridge (`scripts/bridge.py`)

MQTT bridge with Home Assistant discovery. Verified end to end 2026-09-10
against Desk Lamp through a local broker: MQTT set → encrypted local
command → bulb, state plus retained discovery published.

## Run

```bash
cp scripts/bulbs.example.yaml scripts/bulbs.yaml  # gitignored, fill enr from capture
chmod 600 scripts/bulbs.yaml
MQTT_HOST=<broker> MQTT_PORT=1883 MQTT_USER=<user> MQTT_PASS=<pass> \
  python3 scripts/bridge.py --config scripts/bulbs.yaml
```

Needs `pyyaml`, `paho-mqtt`, `pycryptodome`
(`nix-shell -p 'python3.withPackages (ps: [ps.pyyaml ps.paho-mqtt ps.pycryptodome])'`).

HA picks up `Desk Lamp` automatically via discovery (`homeassistant/light/...`).
No HA config changes. Entities support on/off, brightness, color temp
(1800-6500 K), RGB. Optimistic mode: app or physical changes do not sync
back (local `get_status` returns nothing).

## Production deploy (not done yet)

Bridge needs broker credentials. Two options:

1. New `roku-bridge` user in `flake/modules/adguard-netbird-appliance.nix`
   mosquitto ACL (`readwrite homeassistant/#`, `readwrite roku/#`), password
   via the existing SOPS plus CI secret pipeline. Shared infra change,
   needs owner deploy through the homelab repo workflow.
2. Reuse an existing broker user and run the bridge as a systemd user
   service on an always-on host with `bulbs.yaml` deployed alongside.

Tokens in `captures/roku_api.jsonl` expire. The bridge itself is fully
local after discovery; only verification reads use cloud.

## Adding a bulb later

1. Append `{"name","mac","ip","enr"}` to `ROKU_BRIDGE_BULBS_JSON` and
   re-play `deploy_zigbee_gateway`. Verified working for a second device
   class: Light Strip `RK_LS` speaks the same `:88` protocol
   and pids as the `RK_BA19C` bulbs.
2. Secret content changes do not restart services on their own. After
   deploy: `sudo systemctl restart roku-bridge-secrets roku-bridge`.
   Check `journalctl -u roku-bridge` for one `discovery + subscribe` line
   per bulb.

# roku-bulb-local

Wireless conversion research: Roku RK_BA19C (rebranded Wyze) to ESPHome for fully local Home Assistant control.

Status: LOCAL CONTROL WORKING (2026-09-10). `scripts/local_set.py` drives the
bulb over LAN via TCP 88 with AES-CBC (`BULB_ENR` env). Factory-mode exploit
shelved unless a bulb without port 88 shows up.

## Hypothesis chain

```text
Roku RK_BA19C = rebranded Wyze color A19
  -> possible shared factory-test mechanism with Wyze WLPA19CV2
  -> UDP factory mode on port 22223 after ~17 power cycles
  -> custom loader via hijack AP
  -> ESPHome -> Home Assistant, 100 percent local
```

Reference: `nickdaria/wyze-bulb-color-pwned` (cloned to `/tmp/wyze-bulb-color-pwned` for study). Key facts extracted from methodology plus `ap_main.c`:

- Factory SSID: `ASDFGHJKLzxcvb`, PASS: `0x82562647`, channel 1
- Hijack AP IP: `192.168.3.168/24`, serves OTA at `http://192.168.3.168:8070/wyze_iot_service.bin`
- Trigger: `hap upgrade <url>` via UDP to port `22223`, bulb replies `upgrading` on accept
- Entry: ~17 power cycles with <3s on-time each, 5s off between cycles. First 3-4 cycles on a provisioned bulb do a factory reset, then green fade indicates counting
- Success signals: blue flash (factory mode), then purple (wyze-loader running, AP `wyze-loader_XXXXXX` at `http://192.168.4.1`)
- Target SoC: ESP32-C3, 4MB flash, DIO, dual OTA slots, no secure boot on WLPA19CV2 sample
- LED driver: BP5758D over I2C, GPIO19 data, GPIO18 clock (see upstream `src/esphome/config.yaml`)
- Stock RK_BA19C per Roku API research: cloud only, nothing listening on TCP, OUI `7C:67:AB`, MAC without separators as `instance_id`

## Safety

Do not probe or disassemble an energized bulb. Mains voltage on PCB. Network and wireless work only. One sacrificial bulb, rest untouched.

## Phase 0 procedure (this week)

1. Record bulb identity in `docs/bulb-inventory.md` (model, fw version, MAC, hardware rev).
2. Isolate on IoT/research VLAN in OPNsense. Record IP and interface.
3. Baseline scans from `scripts/` (nix shell provides tools):
   `sudo nmap -sS -sV -p- <BULB_IP>`
   `sudo nmap -sU --top-ports 200 <BULB_IP>`
4. Capture per action with tcpdump:
   `sudo tcpdump -ni <iface> host <BULB_IP> -w captures/<action>.pcap`
   Actions: power on, power off, brightness, color, CCT, factory reset, pairing.
5. Look for LAN broadcasts, multicast, UDP discovery, provisioning frames.
6. Factory-mode detection experiment: run hijack AP nearby (ESP32-S3 or Linux hostapd, see `docs/factory-mode-detection.md`), power cycle sacrificial bulb per sequence, run `scripts/detect_factory_mode.py` in listen-only mode first. Do not send `hap upgrade` until broadcast behavior is confirmed and logged.

Decision points:

- Best: RK_BA19C probes for `ASDFGHJKLzxcvb` or broadcasts on UDP 22223. Adapt loader and ESPHome config next.
- Middle: factory mode exists with different IDs or packet layout. Real RE project, upstream code is the reference implementation.
- Worst: different hardware entirely. Drop to PCB and firmware layer (Ghidra, partition table at 0x8000, OTA_0 at 0x10000).

## Layout

- `docs/bulb-inventory.md`: your bulbs, fill in before any test.
- `docs/factory-mode-detection.md`: exact power cycle script and what to log.
- `docs/wyze-reference.md`: pins, constants, and log signatures worth grepping.
- `scripts/detect_factory_mode.py`: passive UDP 22223 listener plus WiFi probe log helper. Stdlib only.
- `scripts/lab-scan.sh`: baseline nmap plus tcpdump wrappers.
- `shell.nix`: ephemeral tools (`nmap`, `wireshark`, `esptool`, `python3`).
- `captures/`: gitignored pcaps.

## Upstream to read before touching the bulb

- `/tmp/wyze-bulb-color-pwned/docs/METHODOLOGY.md`
- `/tmp/wyze-bulb-color-pwned/src/wyze-hijack-ap/main/ap_main.c`
- `/tmp/wyze-bulb-color-pwned/src/wyze-loader/README.md` (endpoints, backup flow)
- `/tmp/wyze-bulb-color-pwned/src/esphome/config.yaml`
- Roku cloud API notes: outbound only, Wyze `set_mesh_property` pids P3, P1501, P1502, P1507

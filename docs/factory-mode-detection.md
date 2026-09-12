# Factory-mode detection experiment

Goal: answer one question without flashing anything: does RK_BA19C emit or respond to the same factory-test traffic as WLPA19CV2?

## Setup

Option A (recommended): flash `wyze-hijack-ap` to a spare ESP32-S3 from upstream (`src/wyze-hijack-ap`, or web flasher in `src/webflasher`). Keep it powered near the bulb. Watch its serial logs for `STATION JOINED` and `DHCP LEASE`.

Option B (no spare ESP32): Linux AP with the exact credentials:

```text
SSID: ASDFGHJKLzxcvb
PASS: 0x82562647
IP:   192.168.3.168/24
```

Bulb hardcodes the OTA URL host, so the AP address matters. Serve nothing on port 8070 during detection.

On a second machine on the same L2, run the passive listener:

```bash
python3 scripts/detect_factory_mode.py --log captures/factory-listen.log
```

## Power cycle sequence

From upstream README plus methodology:

1. Bulb on an easy switch (power strip or wall switch).
2. On until green fade appears, then immediately off. Keep off 5s.
3. If bulb was provisioned, first 3-4 cycles do a factory reset. Green counting starts after that.
4. Repeat to ~17 cycles. Leave it on after the last cycle.
5. Watch for blue flash (factory mode). Do not interrupt.

Log wall-clock time plus cycle count for each toggle. Correlate with first UDP broadcast in the listener log.

## What to record

- Cycle number of first probe for `ASDFGHJKLzxcvb` (check hijack AP logs).
- First UDP 22223 broadcast contents (model string, version, interval).
- DHCP hostname or MAC, assigned IP.
- Any `upgrading` reply: only possible if something sent `hap upgrade`; the detector script never does, so its presence means the hijack AP fired.
- Negative result counts too: no probe after 20 cycles on two attempts.

## Safety and stop rules

- Stop after two full 20-cycle runs with no factory traffic. Move to pcap review, not more cycling.
- Never point `hap upgrade` at the Roku bulb until broadcast behavior matches and you have a flash backup plan via `wyze-loader` endpoints (`/dump`, `/ota`, `/setboot`).
- Keep captures in `captures/` (gitignored).

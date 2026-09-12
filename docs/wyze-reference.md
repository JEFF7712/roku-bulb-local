# Wyze reference specifics (from `/tmp/wyze-bulb-color-pwned`)

## Wireless constants

- `AP_SSID ASDFGHJKLzxcvb`, `AP_PASS 0x82562647`, channel 1
- `SERVER_PORT 8070`, `FACTORY_UDP_PORT 22223`
- Default OTA: `http://192.168.3.168:8070/wyze_iot_service.bin`
- Trigger format: `hap upgrade <url>`, success reply starts with `upgrading`
- Trigger retry: 4 attempts, 1.5s apart, 4s delay after DHCP lease

## Firmware signatures (WLPA19CV2 sample)

- Boot: `ESP-ROM:esp32c3-api1-20210207`, chip ESP32-C3 QFN32 rev v0.3, 4MB XMC flash
- App: project `wyze_bulb`, version `HL_A19C2_1.0.2.6-dirty`, IDF `2cbc2fea-dirty`
- Log markers worth grepping a Roku dump for: `fun_fac`, `in old count`, `fac.old_flag`, `fac.factory_complete_flag`, `fac wifi_rssi`, `FAC TEST`, `app_service`, `mdebug_log`
- Power-cycle counter at `0x420169c6`, factory task spawned at `0x42016056`, UDP handler near `0x42015bcc`, OTA task near `0x4201c42a`
- Partition: table at `0x8000`, dual OTA, OTA_1 erased in sample, OTA_0 at `0x10000-0x1E0000`, unmodified IDF bootloader

## Loader and ESPHome

- `wyze-loader` AP `wyze-loader_XXXXXX`, web UI at `http://192.168.4.1`
- Backup first via `/dump` or raw offset/size, then `/ota` to inactive slot, `/setboot`, `/reboot`
- ESPHome: `esp32-c3-devkitm-1`, Arduino, BP5758D on GPIO19 data and GPIO18 clock, channels 1 blue, 2 green, 3 red, 4 white, RGBW light

## Roku cloud notes (Metrix187 PROTOCOL.md)

- Stock does outbound only, no listening TCP found
- Rack: Roku `POST iot-devices.prod.mobile.roku.com/devices/{id}/command`, Wyze `POST api.wyzeiot.com/app/v2/auto/run_action_list` with `set_mesh_property`, `provider_key RK_BA19C`
- Pids: P3 power 1/0, P1501 brightness 1-100, P1502 white temp ~2700-6500, P1507 RGB hex
- Tokens cached, Wyze token is the only secret needed for all-Wyze path

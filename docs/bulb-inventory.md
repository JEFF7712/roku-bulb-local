# Bulb inventory (recorded 2026-09-10)

| Label | Retail model | Provider key (expected) | Firmware | MAC | IP | Notes |
|---|---|---|---|---|---|---|
| sacrificial-1 | BC1000P2R | RK_BA19C (per Roku/Wyze API research) | 1.1.1.15 | 7C:67:AB:AA:BB:CC | 192.168.1.50 | reachable, same L2 as lab machine. Power-strip circuit for switching |

OUI check passes: `7C:67:AB` matches known Roku OUI. Wyze exploit sample was `68:67:25` at app `HL_A19C2_1.0.2.6-dirty`, so MAC alone does not confirm shared platform. Factory-mode detection will decide that.

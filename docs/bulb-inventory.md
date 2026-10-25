# Bulb inventory (example values, fill in your own before any test)

| Label | Retail model | Provider key (expected) | Firmware | MAC | IP | Notes |
|---|---|---|---|---|---|---|
| sacrificial-1 | BC1000P2R | RK_BA19C (per Roku/Wyze API research) | 1.1.1.15 | 7C:67:AB:AA:BB:CC | 192.168.1.50 | reachable, same L2 as lab machine. Power-strip circuit for switching |

OUI check: `7C:67:AB` matches the known Roku OUI. The Wyze exploit sample was
`68:67:25` at app `HL_A19C2_1.0.2.6-dirty`, so MAC alone does not confirm a
shared platform. Factory-mode detection will decide that.

Do not commit real MACs or IPs to a public copy of this repo.

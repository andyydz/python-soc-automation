# SENTINEL: Evidence-Driven SOC Detection, Investigation and Response Lab

An isolated virtual SOC lab built around Wazuh and Sysmon. It is used to practice the detect → investigate → document loop with evidence for every claim.

> Student lab project. Everything runs in a local virtual environment. Nothing here is a production deployment.

## Overview

SENTINEL models a small enterprise network. Attacks are run from a Kali Linux VM against a monitored Ubuntu endpoint, detections are built and tested in Wazuh, and each investigation is documented with its evidence.

**Rule:** no alert, screenshot, or result is fabricated. Everything documented here comes from actual lab runs.

## Lab Environment

| Component | Detail |
|-----------|--------|
| Hypervisor | Oracle VirtualBox |
| SIEM / XDR | Wazuh 4.14.8 (manager: `SENTINEL-WAZUH`) |
| Monitored endpoint | Ubuntu 24.04 (agent: `SENTINEL-LINUX01`) |
| Attacker | Kali Linux 2026.2 |
| Telemetry | Wazuh File Integrity Monitoring (`/home`), Sysmon (via EVTX replay) |
| Network | Isolated VirtualBox network `10.10.10.0/24` between lab VMs; the Wazuh VM also has NAT for outbound access |

## What It Covers

- Custom Wazuh detection rules, including FIM rules and SSH brute-force rules `100200` (Level 5) and `100201` (Level 10, six matching failures within 60 seconds from the same source IP)
- Sysmon event replay: EVTX converted with `python-evtx` (`scripts/evtx_to_wazuh.py`) and ingested by the manager's logcollector
- Written investigations (for example `investigations/CASE-001.md`) with an evidence index and validation notes
- Detections mapped to MITRE ATT&CK

## Documentation

Detailed documentation is in [`docs/`](docs/) (`01` to `08`), including [architecture](docs/03-architecture.md) and [detection engineering](docs/05-detection-engineering.md).

## Relationship to python-soc-automation

[python-soc-automation](https://github.com/andyydz/python-soc-automation) is a separate repository. It processes exported alert files from this lab. There is no live integration between the two, and it is not connected to the production Wazuh deployment.

## Limitations

- Single-lab, virtual environment only
- No real-world production traffic or live threat data
- No claim of autonomous response or enterprise readiness

## Author

[andyydz](https://github.com/andyydz)

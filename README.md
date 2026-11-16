# Snort IDS with Custom Rules (Project Code: CSL-G36)

- **Student Name:** Priyanshu Joshi
- **Roll No:** 23ESKCY042
- **Class / Batch:** B.Tech VII Sem - CSE (IoT), Section A, Batch G2
- **Course:** Cyber Security Lab (7CS4-22), SKIT Jaipur
- **Linked Syllabus Experiment:** Exp 7 - Intrusion Detection System

## Included Files
1. `local.rules` — Custom Snort rules (`SID 1000001`–`1000006`) for TCP SYN Port Scan, ICMP Ping Flood, SSH Brute-Force, and Suspicious HTTP payloads (Directory Traversal, SQL Injection, Scanner User-Agents).
2. `snort_custom.conf` — Network variable (`$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS`) and output configuration snippet for `/etc/snort/snort.conf`.
3. `attack_simulator.py` — Scapy/urllib-based controlled test script to simulate all four attack categories inside an isolated lab network.
4. `alert_analyzer.py` — Python log parser to summarize triggered SIDs, alert counts, timestamps, and offending source IPs.
5. `sample_alert.log` — Sample fast-alert output for offline testing of `alert_analyzer.py`.

## Quick Setup & Execution (Ubuntu / Kali Lab VMs)
```bash
# 1. Install Snort and Python dependencies
sudo apt update && sudo apt install -y snort python3-scapy

# 2. Copy custom rules to Snort rules directory
sudo cp local.rules /etc/snort/rules/local.rules

# 3. Validate Snort configuration
sudo snort -T -c /etc/snort/snort.conf

# 4. Run Snort in NIDS console alert mode on Host-Only interface (e.g., eth1 / enp0s8)
sudo snort -A fast -q -c /etc/snort/snort.conf -i enp0s8 -l /var/log/snort

# 5. From Attacker VM, trigger simulated attacks
sudo python3 attack_simulator.py --target 192.168.56.101 --attack all

# 6. Parse and summarize alerts on Target VM
python3 alert_analyzer.py --log /var/log/snort/alert
```

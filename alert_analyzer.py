#!/usr/bin/env python3
"""
Snort Fast Alert Log Parser & Security Summary Generator
Student: Priyanshu Joshi | Roll No: 23ESKCY042 | Project Code: CSL-G36
Course: Cyber Security Lab (7CS4-22) - SKIT Jaipur
"""

import argparse
import re
from collections import Counter, defaultdict

ALERT_PATTERN = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s+(?P<classtype>.*?)\]\s+)?"
    r"(?:\[Priority:\s+(?P<priority>\d+)\]\s+)?"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src>[\d\.]+(?::\d+)?)\s+->\s+(?P<dst>[\d\.]+(?::\d+)?)"
)


def parse_snort_log(log_path: str):
    alerts = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = ALERT_PATTERN.search(line)
                if match:
                    alerts.append(match.groupdict())
    except FileNotFoundError:
        print(f"[!] Error: Log file '{log_path}' not found.")
        return []
    return alerts


def generate_summary(alerts):
    if not alerts:
        print("[*] No matching Snort alerts found in the specified log file.")
        return

    sid_counts = Counter()
    sid_messages = {}
    src_ip_counts = Counter()
    proto_counts = Counter()
    timeline = defaultdict(list)

    for a in alerts:
        sid = a["sid"]
        sid_counts[sid] += 1
        sid_messages[sid] = a["msg"]
        src_ip = a["src"].split(":")[0]
        src_ip_counts[src_ip] += 1
        proto_counts[a["proto"]] += 1
        timeline[sid].append(a["timestamp"])

    print("=" * 78)
    print(" SNORT IDS ALERT ANALYSIS REPORT | 23ESKCY042 - Priyanshu Joshi (CSL-G36)")
    print("=" * 78)
    print(f"Total Triggered Alerts : {len(alerts)}")
    print(f"Unique Rules Triggered : {len(sid_counts)}")
    print(f"Unique Source IPs      : {len(src_ip_counts)}\n")

    print("-" * 78)
    print(f"{'SID':<10} {'Count':<8} {'First Seen':<20} {'Alert Message'}")
    print("-" * 78)
    for sid, count in sid_counts.most_common():
        first_seen = timeline[sid][0]
        print(f"{sid:<10} {count:<8} {first_seen:<20} {sid_messages[sid]}")

    print("\n" + "-" * 78)
    print("TOP OFFENDING SOURCE IP ADDRESSES")
    print("-" * 78)
    for ip, count in src_ip_counts.most_common():
        print(f"  {ip:<20} -> {count} alerts")

    print("\n" + "-" * 78)
    print("PROTOCOL DISTRIBUTION")
    print("-" * 78)
    for proto, count in proto_counts.most_common():
        print(f"  {proto:<10} -> {count} alerts")
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(description="Parse and summarize Snort fast alert logs.")
    parser.add_argument(
        "--log",
        default="/var/log/snort/alert",
        help="Path to Snort fast alert log file (default: /var/log/snort/alert)"
    )
    args = parser.parse_args()
    alerts = parse_snort_log(args.log)
    generate_summary(alerts)


if __name__ == "__main__":
    main()

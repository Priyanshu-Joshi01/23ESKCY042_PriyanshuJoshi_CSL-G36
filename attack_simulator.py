#!/usr/bin/env python3
"""
Controlled Network Attack Simulator for Snort IDS Verification
Student: Priyanshu Joshi | Roll No: 23ESKCY042 | Project Code: CSL-G36
Course: Cyber Security Lab (7CS4-22) - SKIT Jaipur

ETHICAL NOTICE: Run ONLY inside an isolated VirtualBox Host-Only / Lab network.
"""

import argparse
import socket
import time
import urllib.request
import urllib.error
from scapy.all import IP, TCP, ICMP, send


def simulate_port_scan(target_ip: str, start_port: int = 20, end_port: int = 45):
    """Simulates a TCP SYN port scan to trigger SID 1000001."""
    print(f"[*] Simulating TCP SYN Port Scan against {target_ip} (ports {start_port}-{end_port})...")
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
    print("[+] TCP SYN Port Scan simulation complete.\n")


def simulate_ping_flood(target_ip: str, count: int = 30):
    """Simulates an ICMP Echo Request flood to trigger SID 1000002."""
    print(f"[*] Simulating ICMP Ping Flood against {target_ip} ({count} packets)...")
    pkt = IP(dst=target_ip) / ICMP(type=8)
    send(pkt, count=count, inter=0.02, verbose=False)
    print("[+] ICMP Ping Flood simulation complete.\n")


def simulate_ssh_bruteforce(target_ip: str, attempts: int = 8):
    """Simulates rapid SSH connection attempts to trigger SID 1000003."""
    print(f"[*] Simulating SSH Brute-Force burst against {target_ip}:22 ({attempts} attempts)...")
    for i in range(attempts):
        pkt = IP(dst=target_ip) / TCP(sport=40000 + i, dport=22, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.2)
    print("[+] SSH Brute-Force simulation complete.\n")


def simulate_suspicious_http(target_ip: str, port: int = 80):
    """Simulates suspicious HTTP payloads to trigger SIDs 1000004, 1000005, 1000006."""
    print(f"[*] Simulating Suspicious HTTP Traffic against http://{target_ip}:{port}...")
    test_cases = [
        ("Directory Traversal", f"http://{target_ip}:{port}/index.php?file=../../../../etc/passwd", "Mozilla/5.0"),
        ("SQL Injection", f"http://{target_ip}:{port}/login.php?id=1%20UNION%20SELECT%201,2,3", "Mozilla/5.0"),
        ("Scanner User-Agent", f"http://{target_ip}:{port}/", "sqlmap/1.7.2#stable (https://sqlmap.org)")
    ]

    for label, url, user_agent in test_cases:
        print(f"    -> Sending {label} request...")
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        try:
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            # Connection refused or 404 is expected if test server is minimal;
            # Snort still inspects the outbound TCP/HTTP payload.
            pass
        time.sleep(0.3)
    print("[+] Suspicious HTTP simulation complete.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Isolated Lab Attack Simulator for Snort Custom Rules (CSL-G36)"
    )
    parser.add_argument("--target", required=True, help="Target VM IP address (e.g., 192.168.56.101)")
    parser.add_argument(
        "--attack",
        choices=["all", "portscan", "pingflood", "ssh", "http"],
        default="all",
        help="Specific attack scenario to simulate (default: all)"
    )
    args = parser.parse_args()

    print("============================================================")
    print(" Snort IDS Controlled Test Suite | 23ESKCY042 Priyanshu Joshi")
    print("============================================================")

    if args.attack in ("all", "portscan"):
        simulate_port_scan(args.target)
    if args.attack in ("all", "pingflood"):
        simulate_ping_flood(args.target)
    if args.attack in ("all", "ssh"):
        simulate_ssh_bruteforce(args.target)
    if args.attack in ("all", "http"):
        simulate_suspicious_http(args.target)

    print("[*] All requested simulations finished. Check /var/log/snort/alert on target VM.")


if __name__ == "__main__":
    main()

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import random

from gen_common import (
    ts_str,
    doc_public_ip,
    add_background_firewall,
    add_background_auth,
    add_background_ids,
    add_background_dns,
    write_all,
)

SEED = 101


#Generates a multi-stage external ransomware-style attack scenario
#This simulates a realistic attack progression from initial access to lateral movement,
#command-and-control communication, and final data exfiltration
def main():
    random.seed(SEED)

    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"

    start = datetime(2026, 2, 10, 10, 0, 0)
    minutes = 60

    #Balanced background traffic with reduced DNS volume to avoid noise dominance
    fw_rate, auth_rate, ids_rate, dns_rate = 34, 6, 5, 4

    fw_rows, au_rows, ids_rows, dns_rows = [], [], [], []

    #Generate baseline normal activity
    add_background_firewall(fw_rows, start, minutes, fw_rate)
    add_background_auth(au_rows, start, minutes, auth_rate)
    add_background_ids(ids_rows, start, minutes, ids_rate)
    add_background_dns(dns_rows, start, minutes, dns_rate)

    attacker = "203.0.113.5"
    vpn_host = "10.0.0.10"
    victim_srv = "10.0.0.20"
    lateral_targets = ["10.0.0.60", "10.0.0.61", "10.0.0.62"]

    # ------------------------------------------------
    # Phase 1 – external access attempts
    #Simulates attacker probing SSH and RDP access points
    # ------------------------------------------------
    for i in range(40):
        t = start + timedelta(minutes=1, seconds=i)
        fw_rows.append([ts_str(t), attacker, vpn_host, 22, "deny"])

    for i in range(30):
        t = start + timedelta(minutes=2, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), attacker, vpn_host, 3389, "deny"])

    # ------------------------------------------------
    # Phase 2 – brute force then successful login
    #Represents credential attack followed by compromise
    # ------------------------------------------------
    for i in range(12):
        t = start + timedelta(minutes=3, seconds=5 + i * 2)
        au_rows.append([ts_str(t), attacker, "fail", "admin"])

    au_rows.append([ts_str(start + timedelta(minutes=3, seconds=40)), attacker, "success", "admin"])

    #Second authentication attack burst later to create multiple alert windows
    for i in range(10):
        t = start + timedelta(minutes=9, seconds=5 + i * 3)
        au_rows.append([ts_str(t), attacker, "fail", "admin"])

    au_rows.append([ts_str(start + timedelta(minutes=9, seconds=45)), attacker, "success", "admin"])

    # ------------------------------------------------
    # Phase 3 – IDS reconnaissance and exploit activity
    #Represents scanning and exploitation attempts detected by IDS
    # ------------------------------------------------
    for i in range(10):
        t = start + timedelta(minutes=4, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), attacker, vpn_host, "ET SCAN Nmap", "high"])

    for i in range(6):
        t = start + timedelta(minutes=4, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), attacker, vpn_host, "ET WEB_SERVER Possible Exploit Attempt", "high"])

    # ------------------------------------------------
    # Phase 4 – internal port scan
    #Attacker begins internal reconnaissance after gaining access
    # ------------------------------------------------
    scan_ports = [21,22,23,25,53,80,110,135,139,143,389,443,445,3389,5985,5986]

    for p in scan_ports:
        t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), victim_srv, lateral_targets[0], p, "deny"])

    # ------------------------------------------------
    # Phase 5 – lateral movement
    #Simulates spreading across internal network
    # ------------------------------------------------
    for host in lateral_targets:

        for _ in range(14):
            t = start + timedelta(minutes=6, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), victim_srv, host, 445, "deny"])

        for _ in range(6):
            t = start + timedelta(minutes=7, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), victim_srv, host, 5985, "allow"])

    # ------------------------------------------------
    # Phase 6 – command-and-control (C2) beaconing
    #Low-frequency periodic communication to external domain
    # ------------------------------------------------
    c2_domain = "control-update.bad-domain.xyz"

    beacon_times = [
        (7,0),(7,30),
        (8,0),(8,30),
        (9,0),(9,30),
    ]

    for minute_offset, sec in beacon_times:
        t = start + timedelta(minutes=minute_offset, seconds=sec)
        dns_rows.append([ts_str(t), victim_srv, c2_domain, "NOERROR"])

    # ------------------------------------------------
    # Phase 7 – outbound staging / data exfiltration
    #Large volume of outbound encrypted traffic
    # ------------------------------------------------
    for _ in range(90):
        t = start + timedelta(minutes=10, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), victim_srv, doc_public_ip(), 443, "allow"])

    # ------------------------------------------------
    # Phase 8 – ransomware / malware indicators
    #High-severity IDS alerts representing final attack stage
    # ------------------------------------------------
    for _ in range(8):
        t = start + timedelta(minutes=10, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), victim_srv, doc_public_ip(),
                         "ET TROJAN Possible C2 Traffic", "high"])

    for _ in range(6):
        t = start + timedelta(minutes=11, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), victim_srv, random.choice(lateral_targets),
                         "ET MALWARE Ransomware Activity", "critical"])

    #Write all generated datasets to disk
    write_all(data_dir, fw_rows, au_rows, ids_rows, dns_rows)


if __name__ == "__main__":
    main()
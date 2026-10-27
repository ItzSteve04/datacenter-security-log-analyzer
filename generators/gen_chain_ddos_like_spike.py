from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import random

from gen_common import (
    ts_str,
    add_background_firewall,
    add_background_auth,
    add_background_ids,
    add_background_dns,
    write_all,
)

SEED = 303


#Generates a focused DDoS-like attack dataset with minimal background noise
#This scenario is designed to make firewall and IDS detections stand out clearly
def main():
    random.seed(SEED)

    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"

    start = datetime(2026, 2, 10, 10, 0, 0)
    minutes = 60

    #Keep background traffic very low so the DDoS pattern dominates
    fw_rate, auth_rate, ids_rate, dns_rate = 12, 1, 1, 1

    fw_rows, au_rows, ids_rows, dns_rows = [], [], [], []

    #Generate low-volume baseline traffic for all log sources
    add_background_firewall(fw_rows, start, minutes, fw_rate)
    add_background_auth(au_rows, start, minutes, auth_rate)
    add_background_ids(ids_rows, start, minutes, ids_rate)
    add_background_dns(dns_rows, start, minutes, dns_rate)

    #Target host for the DDoS-style flood
    target = "10.0.0.40"

    #Small set of repeat attacker IPs to simulate a botnet-like pattern
    bot_ips = [
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.12",
        "203.0.113.13",
        "203.0.113.14",
        "198.51.100.20",
        "198.51.100.21",
        "198.51.100.22",
    ]

    #Minute 5: heavy deny flood against port 443
    #Designed to create a strong firewall traffic spike and repeated deny pattern
    for src in bot_ips:
        for _ in range(90):
            t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), src, target, 443, "deny"])

    #Minute 6: sustained but slightly reduced pressure
    for src in bot_ips:
        for _ in range(55):
            t = start + timedelta(minutes=6, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), src, target, 443, "deny"])

    #Add some multi-port abuse so firewall detection is not limited to one port
    ddos_ports = [80, 443, 8080]
    for src in bot_ips[:4]:
        for p in ddos_ports:
            for _ in range(8):
                t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
                fw_rows.append([ts_str(t), src, target, p, "deny"])

    #IDS burst aligned with the flood traffic
    #Simulates IDS engines recognising denial-of-service patterns
    for src in bot_ips:
        for _ in range(4):
            t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
            ids_rows.append([ts_str(t), src, target, "ET DOS Possible Flood", "high"])

    for src in bot_ips[:5]:
        for _ in range(3):
            t = start + timedelta(minutes=6, seconds=random.randint(0, 59))
            ids_rows.append([ts_str(t), src, target, "ET DOS Possible Flood", "high"])

    #Add a few critical severity IDS alerts for stronger visibility in analysis results
    for src in bot_ips[:3]:
        t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), src, target, "ET DOS Distributed Flood", "critical"])

    #Write all generated datasets to disk
    write_all(data_dir, fw_rows, au_rows, ids_rows, dns_rows)


if __name__ == "__main__":
    main()
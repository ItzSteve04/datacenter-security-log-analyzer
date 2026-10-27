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

SEED = 202


#Generates an insider data exfiltration scenario
#Focuses on subtle internal misuse rather than loud external attacks,
#with DNS and outbound traffic as the primary indicators
def main():
    random.seed(SEED)

    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"

    start = datetime(2026, 2, 10, 10, 0, 0)
    minutes = 60

    #Lower authentication noise, keep DNS and firewall stronger
    #to reflect exfiltration-focused behaviour
    fw_rate, auth_rate, ids_rate, dns_rate = 26, 4, 3, 18

    fw_rows, au_rows, ids_rows, dns_rows = [], [], [], []

    #Generate baseline normal activity
    add_background_firewall(fw_rows, start, minutes, fw_rate)
    add_background_auth(au_rows, start, minutes, auth_rate)
    add_background_ids(ids_rows, start, minutes, ids_rate)
    add_background_dns(dns_rows, start, minutes, dns_rate)

    insider = "10.0.0.30"
    target_db = "10.0.0.61"

    # ------------------------------------------------
    # Phase 1 – initial authentication abuse
    #Subtle failed logins followed by success for a service account
    # ------------------------------------------------
    for i in range(8):
        t = start + timedelta(minutes=9, seconds=5 + i * 3)
        au_rows.append([ts_str(t), insider, "fail", "svc_backup"])

    au_rows.append([ts_str(start + timedelta(minutes=9, seconds=40)), insider, "success", "svc_backup"])

    #Second smaller auth burst later to create another detection window
    for i in range(6):
        t = start + timedelta(minutes=24, seconds=10 + i * 4)
        au_rows.append([ts_str(t), insider, "fail", "svc_backup"])

    au_rows.append([ts_str(start + timedelta(minutes=24, seconds=45)), insider, "success", "svc_backup"])

    # ------------------------------------------------
    # Phase 2 – suspicious DNS behaviour
    #Primary indicator of exfiltration via domain churn and beaconing
    # ------------------------------------------------
    for i in range(22):
        t = start + timedelta(minutes=10, seconds=i * 2)
        dns_rows.append([ts_str(t), insider, f"exf{i:02d}.data-sync.bad-domain.xyz", "NOERROR"])

    #NXDOMAIN spike to simulate failed or probing lookups
    for i in range(18):
        t = start + timedelta(minutes=20, seconds=i * 2)
        dns_rows.append([ts_str(t), insider, f"lookup{i:02d}.ghost-domain.xyz", "NXDOMAIN"])

    #Beacon-like repeated communication to a control domain
    beacon_domain = "sync-control.bad-domain.xyz"
    beacon_points = [
        (30, 0), (30, 30),
        (31, 0), (31, 30),
        (32, 0), (32, 30),
        (33, 0), (33, 30),
    ]
    for minute_offset, sec in beacon_points:
        t = start + timedelta(minutes=minute_offset, seconds=sec)
        dns_rows.append([ts_str(t), insider, beacon_domain, "NOERROR"])

    # ------------------------------------------------
    # Phase 3 – outbound exfiltration
    #Main signal for firewall-based anomaly detection
    # ------------------------------------------------
    for _ in range(75):
        t = start + timedelta(minutes=11, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), insider, doc_public_ip(), random.choice([443, 8443]), "allow"])

    for _ in range(65):
        t = start + timedelta(minutes=21, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), insider, doc_public_ip(), random.choice([443, 8443]), "allow"])

    #Additional later-stage exfiltration window
    for _ in range(55):
        t = start + timedelta(minutes=34, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), insider, doc_public_ip(), 443, "allow"])

    # ------------------------------------------------
    # Phase 4 – light IDS support
    #IDS provides supporting evidence but is not dominant in this scenario
    # ------------------------------------------------
    for _ in range(2):
        t = start + timedelta(minutes=11, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), insider, target_db,
                         "ET POLICY Windows executable download", "high"])

    for _ in range(2):
        t = start + timedelta(minutes=21, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), insider, doc_public_ip(),
                         "ET POLICY Suspicious Internal Transfer", "high"])

    for _ in range(1):
        t = start + timedelta(minutes=34, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), insider, doc_public_ip(),
                         "ET TROJAN Possible Data Staging", "medium"])

    #Write all generated datasets to disk
    write_all(data_dir, fw_rows, au_rows, ids_rows, dns_rows)


if __name__ == "__main__":
    main()
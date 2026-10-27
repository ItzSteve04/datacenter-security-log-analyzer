from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import random

from gen_common import (
    ts_str,
    doc_public_ip,
    rand_domain,
    internal_ip,
    add_background_firewall,
    add_background_auth,
    add_background_ids,
    add_background_dns,
    write_all,
)

#Generates a chained multi-stage attack dataset across firewall, auth, IDS, and DNS logs
#This scenario is more advanced than the basic generator and is designed to simulate
#coordinated attacks that unfold over multiple stages
def main():
    random.seed()

    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"

    start = datetime(2026, 2, 10, 10, 0, 0)
    minutes = 60

    #Balanced baseline rates for each source type
    #Firewall highest volume, DNS second, auth moderate, IDS lowest
    fw_rate, auth_rate, ids_rate, dns_rate = 48, 12, 10, 30

    fw_rows, au_rows, ids_rows, dns_rows = [], [], [], []

    #Generate normal background traffic before injecting attack chains
    add_background_firewall(fw_rows, start, minutes, fw_rate)
    add_background_auth(au_rows, start, minutes, auth_rate)
    add_background_ids(ids_rows, start, minutes, ids_rate)
    add_background_dns(dns_rows, start, minutes, dns_rate)

    # -----------------------
    # Chain A: external ransomware-style attack sequence
    #Simulates an attacker moving from reconnaissance to compromise,
    #lateral movement, suspicious DNS activity, and outbound exfiltration
    # -----------------------
    attacker = "203.0.113.5"
    vpn_host = "10.0.0.10"
    victim_srv = "10.0.0.20"
    lateral_targets = ["10.0.0.60", "10.0.0.61", "10.0.0.62"]

    #Repeated external denies against a VPN or access host
    for i in range(24):
        t = start + timedelta(minutes=1, seconds=i * 2)
        fw_rows.append([ts_str(t), attacker, vpn_host, 22, "deny"])

    #Authentication failures followed by a success
    for i in range(6):
        t = start + timedelta(minutes=3, seconds=10 + i * 3)
        au_rows.append([ts_str(t), attacker, "fail", "admin", vpn_host])
    au_rows.append([ts_str(start + timedelta(minutes=3, seconds=40)), attacker, "success", "admin", vpn_host])

    #Reconnaissance and exploit-style IDS alerts
    ids_rows.append([ts_str(start + timedelta(minutes=3, seconds=35)), attacker, vpn_host, "ET SCAN Nmap", "high"])
    for i in range(8):
        t = start + timedelta(minutes=4, seconds=5 + i * 4)
        ids_rows.append([ts_str(t), attacker, vpn_host, "ET WEB_SERVER Possible Exploit Attempt", "high"])

    #Port scan activity to trigger firewall port-scan detection
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5985, 5986, 8080]
    for p in scan_ports:
        t = start + timedelta(minutes=4, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), victim_srv, lateral_targets[0], p, "deny"])

    #Lateral movement from compromised internal host to other internal systems
    for host in lateral_targets:
        for _ in range(10):
            t = start + timedelta(minutes=5, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), victim_srv, host, 445, "deny"])
        for _ in range(8):
            t = start + timedelta(minutes=6, seconds=random.randint(0, 59))
            fw_rows.append([ts_str(t), victim_srv, host, 5985, "allow"])

    #Suspicious DNS lookups / beaconing-like behaviour
    for i in range(16):
        t = start + timedelta(minutes=7, seconds=i * 2)
        dns_rows.append([ts_str(t), victim_srv, rand_domain(benign_bias=0.02), "NOERROR"])

    #Outbound exfiltration-style traffic
    for _ in range(70):
        t = start + timedelta(minutes=8, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), victim_srv, doc_public_ip(), 443, "allow"])

    #IDS malware / C2 alert burst
    ids_rows.append([ts_str(start + timedelta(minutes=8, seconds=40)), victim_srv, "8.8.8.8",
                     "ET TROJAN Possible C2 Traffic", "critical"])
    for i in range(10):
        t = start + timedelta(minutes=8, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), victim_srv, doc_public_ip(), "ET TROJAN Possible C2 Traffic", "high"])

    # -----------------------
    # Chain B: insider / service-account exfiltration
    #Simulates misuse of an internal or service account leading to suspicious DNS
    #and outbound transfer behaviour
    # -----------------------
    insider = "10.0.0.30"
    target_db = "10.0.0.61"

    #Service account failures followed by a success
    for i in range(5):
        t = start + timedelta(minutes=12, seconds=5 + i * 3)
        au_rows.append([ts_str(t), insider, "fail", "svc_backup", target_db])
    au_rows.append([ts_str(start + timedelta(minutes=12, seconds=35)), insider, "success", "svc_backup", target_db])

    #Suspicious DNS behaviour
    for i in range(40):
        t = start + timedelta(minutes=13, seconds=i * 2)
        dns_rows.append([ts_str(t), insider, rand_domain(benign_bias=0.08), "NOERROR"])

    #NXDOMAIN-heavy traffic to simulate failed or suspicious lookups
    for i in range(30):
        t = start + timedelta(minutes=13, seconds=10 + i * 2)
        dns_rows.append([ts_str(t), insider, rand_domain(benign_bias=0.0), "NXDOMAIN"])

    #Outbound transfer behaviour from insider host
    for _ in range(60):
        t = start + timedelta(minutes=14, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), insider, doc_public_ip(), random.choice([443, 8443]), "allow"])

    #IDS alerts around insider activity
    ids_rows.append([ts_str(start + timedelta(minutes=14, seconds=15)), insider, target_db,
                     "ET POLICY Windows executable download", "high"])
    for i in range(8):
        t = start + timedelta(minutes=14, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), insider, target_db, "ET POLICY Suspicious Internal Transfer", "high"])

    # -----------------------
    # Chain C: DDoS-like denial burst
    #Simulates a concentrated denial-of-service style flood against one target
    # -----------------------
    target = "10.0.0.40"

    #Main flood period
    for _ in range(520):
        t = start + timedelta(minutes=16, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), doc_public_ip(), target, 443, "deny"])

    #Residual pressure in the following minute
    for _ in range(180):
        t = start + timedelta(minutes=17, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), doc_public_ip(), target, 443, "deny"])

    #IDS alerts indicating possible DoS activity
    for i in range(14):
        t = start + timedelta(minutes=16, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), doc_public_ip(), target, "ET DOS Possible Flood", "high"])

    for i in range(8):
        t = start + timedelta(minutes=17, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), doc_public_ip(), target, "ET DOS Possible Flood", "high"])

    # -----------------------
    # Chain D: dedicated DNS anomaly window
    #Simulates concentrated suspicious DNS activity from one host
    # -----------------------
    dns_host = "10.0.0.50"

    for i in range(24):
        t = start + timedelta(minutes=19, seconds=i * 2)
        dns_rows.append([ts_str(t), dns_host, rand_domain(benign_bias=0.0), "NXDOMAIN"])

    for i in range(16):
        t = start + timedelta(minutes=20, seconds=i * 3)
        dns_rows.append([ts_str(t), dns_host, rand_domain(benign_bias=0.03), "NOERROR"])

    # -----------------------
    # Chain E: dedicated repeated-deny window
    #Designed specifically to trigger repeated deny detection
    # -----------------------
    noisy_src = "203.0.113.77"
    noisy_dst = "10.0.0.70"

    for _ in range(42):
        t = start + timedelta(minutes=21, seconds=random.randint(0, 59))
        fw_rows.append([ts_str(t), noisy_src, noisy_dst, random.choice([22, 23, 445, 3389]), "deny"])

    # -----------------------
    # Chain F: dedicated IDS burst
    #Designed specifically to trigger IDS burst detection
    # -----------------------
    ids_src = "198.51.100.45"
    ids_dst = "10.0.0.80"

    for i in range(24):
        t = start + timedelta(minutes=22, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), ids_src, ids_dst, "ET SCAN Potential Recon Activity", "high"])

    for i in range(10):
        t = start + timedelta(minutes=23, seconds=random.randint(0, 59))
        ids_rows.append([ts_str(t), ids_src, ids_dst, "ET EXPLOIT Possible Remote Code Execution", "critical"])

    #Write all generated datasets to disk
    write_all(data_dir, fw_rows, au_rows, ids_rows, dns_rows)


if __name__ == "__main__":
    main()
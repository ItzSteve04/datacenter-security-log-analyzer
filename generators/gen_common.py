from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import random
import string

import pandas as pd


#Formats datetime into consistent string format for logs
def ts_str(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S")


#Adds small random time variation to avoid perfectly uniform timestamps
def jitter(t: datetime, sec: int = 59) -> datetime:
    return t + timedelta(seconds=random.randint(0, sec))


#Generates safe example public IPs (documentation ranges)
def doc_public_ip() -> str:
    prefix = random.choice(["203.0.113.", "198.51.100.", "192.0.2."])
    return prefix + str(random.randint(1, 254))


#Generates internal/private IP addresses (datacenter style)
def internal_ip() -> str:
    return f"10.0.0.{random.randint(2, 254)}"


#Generates realistic DNS queries with mostly benign domains
#Occasionally produces suspicious/random domains
def rand_domain(benign_bias: float = 0.9) -> str:
    benign = [
        "ul.ie", "microsoft.com", "github.com", "cloudflare.com",
        "windowsupdate.com", "ubuntu.com", "docker.com",
        "ntp.org", "letsencrypt.org", "example.com",
    ]
    if random.random() < benign_bias:
        base = random.choice(benign)
        if random.random() < 0.4:
            sub = random.choice(["login", "cdn", "api", "download", "updates", "static"])
            return f"{sub}.{base}"
        return base

    token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    tld = random.choice(["xyz", "top", "biz", "ru", "cn"])
    return f"{token}.bad-domain.{tld}"


#Creates variation in event rates to simulate realistic traffic fluctuations
def variable_rate(base_rate: int, variation: float = 0.18, minimum: int = 1) -> int:
    low = max(minimum, int(base_rate * (1.0 - variation)))
    high = max(low, int(base_rate * (1.0 + variation)))
    return random.randint(low, high)


#Generates baseline firewall traffic with realistic mix of internal and external activity
def add_background_firewall(rows: list, start: datetime, minutes: int, rate_per_min: int) -> None:
    ports = [22, 53, 80, 443, 3389, 445, 3306, 6379, 8080, 8443]
    for m in range(minutes):
        base = start + timedelta(minutes=m)
        minute_rate = variable_rate(rate_per_min, variation=0.15, minimum=max(8, rate_per_min // 2))

        for _ in range(minute_rate):
            t = jitter(base)
            src = internal_ip() if random.random() < 0.72 else doc_public_ip()
            dst = internal_ip()
            dpt = random.choice(ports)
            action = "allow" if random.random() < 0.86 else "deny"
            rows.append([ts_str(t), src, dst, dpt, action])


#Generates baseline authentication activity (mostly internal successful logins)
def add_background_auth(rows: list, start: datetime, minutes: int, rate_per_min: int) -> None:
    users = ["alice", "bob", "charlie", "dana", "eve", "jenkins", "svc_backup", "svc_monitor"]
    for m in range(minutes):
        base = start + timedelta(minutes=m)
        minute_rate = variable_rate(rate_per_min, variation=0.12, minimum=max(5, rate_per_min // 2))

        for _ in range(minute_rate):
            t = jitter(base)
            client = internal_ip() if random.random() < 0.93 else doc_public_ip()
            user = random.choice(users)
            result = "success" if random.random() < 0.84 else "fail"
            server = internal_ip()
            rows.append([ts_str(t), client, result, user, server])


#Generates baseline IDS alerts with mostly low/medium severity events
def add_background_ids(rows: list, start: datetime, minutes: int, rate_per_min: int) -> None:
    sigs = [
        "ET POLICY Windows executable download",
        "ET INFO TLS Certificate Observed",
        "ET WEB_CLIENT Suspicious User-Agent",
        "ET POLICY External IP Check",
        "ET DNS Query for .local TLD",
        "ET INFO Observed DNS Query",
        "ET SCAN Potential Recon Activity",
    ]
    sevs = ["low", "low", "low", "medium", "medium", "medium", "high"]

    for m in range(minutes):
        base = start + timedelta(minutes=m)
        minute_rate = variable_rate(rate_per_min, variation=0.20, minimum=max(3, rate_per_min // 2))

        for _ in range(minute_rate):
            t = jitter(base)
            src = internal_ip() if random.random() < 0.70 else doc_public_ip()
            dest = internal_ip()
            sig = random.choice(sigs)
            sev = random.choice(sevs)
            rows.append([ts_str(t), src, dest, sig, sev])


#Generates baseline DNS traffic with mostly normal domain lookups
def add_background_dns(rows: list, start: datetime, minutes: int, rate_per_min: int) -> None:
    for m in range(minutes):
        base = start + timedelta(minutes=m)
        minute_rate = variable_rate(rate_per_min, variation=0.15, minimum=max(6, rate_per_min // 2))

        for _ in range(minute_rate):
            t = jitter(base)
            src = internal_ip()
            query = rand_domain(benign_bias=0.95)
            rcode = "NOERROR" if random.random() < 0.97 else "NXDOMAIN"
            rows.append([ts_str(t), src, query, rcode])


#Writes all generated datasets to CSV files and prints summary information
def write_all(data_dir: Path, fw_rows: list, au_rows: list, ids_rows: list, dns_rows: list) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)

    fw = pd.DataFrame(fw_rows, columns=["timestamp", "src_ip", "dst_ip", "dst_port", "action"]).sort_values("timestamp")
    au = pd.DataFrame(au_rows, columns=["time", "client_ip", "result", "user", "server"]).sort_values("time")
    ids = pd.DataFrame(ids_rows, columns=["ts", "src", "dest", "sig", "sev"]).sort_values("ts")
    dns = pd.DataFrame(dns_rows, columns=["timestamp", "src_ip", "query", "rcode"]).sort_values("timestamp")

    fw.to_csv(data_dir / "firewall.csv", index=False)
    au.to_csv(data_dir / "auth.csv", index=False)
    ids.to_csv(data_dir / "ids.csv", index=False)
    dns.to_csv(data_dir / "dns.csv", index=False)

    #Prints output file locations and row counts for verification
    print("Generated:")
    print(f"  {data_dir / 'firewall.csv'}  rows={len(fw)}")
    print(f"  {data_dir / 'auth.csv'}      rows={len(au)}")
    print(f"  {data_dir / 'ids.csv'}       rows={len(ids)}")
    print(f"  {data_dir / 'dns.csv'}       rows={len(dns)}")
    print("\nNow run: python src/main.py")
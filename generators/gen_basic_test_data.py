from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta
import random
import string

import pandas as pd


#Fixed seed for reproducible datasets
SEED = 42


#Generates either safe example public IPs or internal/private IPs
def _rand_ip(public: bool = True) -> str:
    if public:
        #Use documentation ranges for safe “public” examples
        return random.choice(["203.0.113.", "198.51.100.", "192.0.2."]) + str(random.randint(1, 254))
    #Internal/private ranges
    r = random.random()
    if r < 0.6:
        return f"10.0.0.{random.randint(1, 254)}"
    if r < 0.85:
        return f"192.168.1.{random.randint(1, 254)}"
    return f"172.16.{random.randint(0, 31)}.{random.randint(1, 254)}"


#Generates usernames representing normal users, service accounts, and admins
def _rand_user() -> str:
    return random.choice([
        "alice", "bob", "charlie", "dana", "eve",
        "svc_backup", "svc_monitor", "admin", "administrator",
        "dbadmin", "jenkins", "kubeadmin"
    ])


#Generates mostly normal domains with occasional suspicious-looking ones
def _rand_domain() -> str:
    base = random.choice([
        "example.com", "microsoft.com", "cloudflare.com",
        "github.com", "openai.com", "ul.ie"
    ])
    if random.random() < 0.92:
        return base
    token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    tld = random.choice(["xyz", "top", "biz", "ru", "cn"])
    return f"{token}.bad-domain.{tld}"


#Random IDS signatures used for synthetic IDS alerts
def _rand_sig() -> str:
    return random.choice([
        "ET SCAN Nmap",
        "ET POLICY PE EXE or DLL Windows file download HTTP",
        "ET EXPLOIT Possible Shellshock",
        "ET TROJAN Possible C2 Traffic",
        "GPL ATTACK_RESPONSE id check returned root",
        "ET WEB_SERVER SQL Injection Attempt",
    ])


#Generates baseline firewall traffic plus forced attack patterns
def generate_firewall(start: datetime, minutes: int, base_rate_per_min: int, out_path: Path) -> None:
    """
    firewall.csv columns:
      timestamp,src_ip,dst_ip,dst_port,action
    """
    rows = []

    #More realistic common service ports
    common_ports = [53, 80, 443, 22, 3389, 445, 3306, 8080]
    common_weights = [10, 18, 28, 7, 5, 6, 5, 4]

    for m in range(minutes):
        t0 = start + timedelta(minutes=m)

        #Baseline traffic: mostly legitimate internal activity with some external access
        for _ in range(base_rate_per_min):
            ts = t0 + timedelta(seconds=random.randint(0, 59))

            traffic_type = random.random()

            #Internal-to-internal east-west traffic
            if traffic_type < 0.55:
                src_ip = _rand_ip(public=False)
                dst_ip = _rand_ip(public=False)
                dst_port = random.choices(common_ports, weights=common_weights, k=1)[0]
                action = "allow" if random.random() < 0.96 else "deny"

            #Internal-to-external outbound traffic
            elif traffic_type < 0.85:
                src_ip = _rand_ip(public=False)
                dst_ip = _rand_ip(public=True)
                dst_port = random.choices([53, 80, 443, 8080], weights=[8, 18, 30, 4], k=1)[0]
                action = "allow" if random.random() < 0.97 else "deny"

            #External-to-internal inbound traffic
            else:
                src_ip = _rand_ip(public=True)
                dst_ip = _rand_ip(public=False)
                dst_port = random.choices([22, 80, 443, 3389, 445], weights=[8, 14, 16, 6, 4], k=1)[0]
                action = "allow" if random.random() < 0.70 else "deny"

            rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, dst_port, action])

        #Short traffic spike to simulate increased inbound pressure
        if m == 5:
            for _ in range(base_rate_per_min * 4):
                ts = t0 + timedelta(seconds=random.randint(0, 59))
                rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), _rand_ip(True), "10.0.0.10", 22, "deny"])

    #Forced brute-force / repeated denies
    brute_ip = "203.0.113.5"
    for k in range(40):
        ts = start + timedelta(minutes=2, seconds=k)
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), brute_ip, "10.0.0.10", 22, "deny"])

    #Forced port scan
    scan_ip = "198.51.100.9"
    ports = list(range(20, 60)) + [80, 443, 3389]
    for p in ports:
        ts = start + timedelta(minutes=3, seconds=random.randint(0, 59))
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), scan_ip, "10.0.0.20", p, "deny"])

    #Forced lateral movement
    lateral_src = "10.0.0.50"
    for host in ["10.0.0.60", "10.0.0.61", "10.0.0.62", "10.0.0.63", "10.0.0.64", "10.0.0.65"]:
        for _ in range(6):
            ts = start + timedelta(minutes=7, seconds=random.randint(0, 59))
            rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), lateral_src, host, 445, "deny"])

    #Forced exfiltration-style outbound behaviour
    ex_src = "10.0.0.20"
    for _ in range(60):
        ts = start + timedelta(minutes=8, seconds=random.randint(0, 59))
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), ex_src, _rand_ip(public=True), 443, "allow"])

    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "dst_port", "action"])
    df = df.sort_values("timestamp")
    df.to_csv(out_path, index=False)


#Generates baseline authentication activity plus suspicious login scenarios
def generate_auth(start: datetime, minutes: int, base_rate_per_min: int, out_path: Path) -> None:
    """
    auth.csv columns:
      time,client_ip,result,user
    """
    rows = []

    normal_users = ["alice", "bob", "charlie", "dana", "eve"]
    service_users = ["svc_backup", "svc_monitor", "jenkins"]
    admin_users = ["admin", "administrator", "dbadmin", "kubeadmin"]

    for m in range(minutes):
        t0 = start + timedelta(minutes=m)

        #Baseline auth activity: mostly internal successful logins
        for _ in range(base_rate_per_min):
            ts = t0 + timedelta(seconds=random.randint(0, 59))

            r = random.random()

            if r < 0.75:
                user = random.choice(normal_users)
                client_ip = _rand_ip(public=False)
                result = "success" if random.random() < 0.92 else "fail"
            elif r < 0.92:
                user = random.choice(service_users)
                client_ip = _rand_ip(public=False)
                result = "success" if random.random() < 0.97 else "fail"
            else:
                user = random.choice(admin_users)
                client_ip = _rand_ip(public=random.random() < 0.20)
                result = "success" if random.random() < 0.85 else "fail"

            rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), client_ip, result, user])

        #Authentication spike at minute 6
        if m == 6:
            for _ in range(base_rate_per_min * 5):
                ts = t0 + timedelta(seconds=random.randint(0, 59))
                rows.append([
                    ts.strftime("%Y-%m-%d %H:%M:%S"),
                    _rand_ip(True),
                    "fail",
                    random.choice(["alice", "bob", "admin"])
                ])

    #Forced failed logins from a single attacker IP
    attacker_ip = "203.0.113.5"
    for k in range(12):
        ts = start + timedelta(minutes=2, seconds=10 + k)
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), attacker_ip, "fail", "alice"])

    #Forced success after failures
    for k in range(6):
        ts = start + timedelta(minutes=4, seconds=20 + k)
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), attacker_ip, "fail", "admin"])
    rows.append([(start + timedelta(minutes=4, seconds=40)).strftime("%Y-%m-%d %H:%M:%S"), attacker_ip, "success", "admin"])

    df = pd.DataFrame(rows, columns=["time", "client_ip", "result", "user"])
    df = df.sort_values("time")
    df.to_csv(out_path, index=False)


#Generates baseline IDS activity plus a forced high-severity alert burst
def generate_ids(start: datetime, minutes: int, base_rate_per_min: int, out_path: Path) -> None:
    """
    ids.csv columns:
      ts,src,dest,sig,sev
    """
    rows = []

    for m in range(minutes):
        t0 = start + timedelta(minutes=m)

        #Baseline IDS logs: mostly low/medium severity, sparse compared to firewall logs
        for _ in range(base_rate_per_min):
            ts = t0 + timedelta(seconds=random.randint(0, 59))
            src = _rand_ip(public=random.random() < 0.25)
            dest = _rand_ip(public=False)
            sig = _rand_sig()
            sev = random.choices(
                ["low", "medium", "high"],
                weights=[55, 35, 10],
                k=1
            )[0]
            rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), src, dest, sig, sev])

    #Forced burst of high/critical IDS alerts
    burst_src = "203.0.113.5"
    for k in range(15):
        ts = start + timedelta(minutes=2, seconds=k)
        rows.append([
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            burst_src,
            "10.0.0.10",
            "ET SCAN Nmap",
            random.choice(["high", "critical"])
        ])

    df = pd.DataFrame(rows, columns=["ts", "src", "dest", "sig", "sev"])
    df = df.sort_values("ts")
    df.to_csv(out_path, index=False)


#Generates baseline DNS traffic plus forced spike behaviour
def generate_dns(start: datetime, minutes: int, base_rate_per_min: int, out_path: Path) -> None:
    """
    dns.csv columns:
      timestamp,src_ip,query,rcode
    """
    rows = []

    normal_domains = [
        "microsoft.com", "cloudflare.com", "github.com",
        "openai.com", "ul.ie", "example.com"
    ]

    for m in range(minutes):
        t0 = start + timedelta(minutes=m)

        #Baseline DNS behaviour: mostly repeated lookups to common domains
        for _ in range(base_rate_per_min):
            ts = t0 + timedelta(seconds=random.randint(0, 59))
            src_ip = _rand_ip(public=False)

            if random.random() < 0.90:
                query = random.choice(normal_domains)
            else:
                query = _rand_domain()

            rcode = "NOERROR" if random.random() < 0.97 else "NXDOMAIN"
            rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), src_ip, query, rcode])

    #Forced domain spike: one internal host queries many unique domains
    spike_src = "10.0.0.20"
    for k in range(30):
        ts = start + timedelta(minutes=3, seconds=k)
        query = f"{k}-{_rand_domain()}"
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), spike_src, query, "NOERROR"])

    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "query", "rcode"])
    df = df.sort_values("timestamp")
    df.to_csv(out_path, index=False)


#Main generator entry point
#Creates all baseline datasets and injects known suspicious scenarios for testing
def main():
    random.seed(SEED)

    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    start = datetime(2026, 2, 10, 10, 0, 0)
    minutes = 60

    #Baseline event rates for each source
    firewall_rate = 35
    auth_rate = 20
    ids_rate = 8
    dns_rate = 25

    generate_firewall(start, minutes, firewall_rate, data_dir / "firewall.csv")
    generate_auth(start, minutes, auth_rate, data_dir / "auth.csv")
    generate_ids(start, minutes, ids_rate, data_dir / "ids.csv")
    generate_dns(start, minutes, dns_rate, data_dir / "dns.csv")

    print("Generated:")
    print(f"  {data_dir / 'firewall.csv'}")
    print(f"  {data_dir / 'auth.csv'}")
    print(f"  {data_dir / 'ids.csv'}")
    print(f"  {data_dir / 'dns.csv'}")
    print("\nNow run: python src/main.py")


if __name__ == "__main__":
    main()
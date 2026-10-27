from __future__ import annotations

import pandas as pd
import ipaddress
import re
from typing import Iterable

#Detects repeated deny events from the same source IP within a time window
def detect_repeated_denies(
    df: pd.DataFrame,
    window_minutes: int = 5,
    threshold: int = 10,
) -> pd.DataFrame:
    """
    Flags source IPs with >= threshold deny events within each time window.

    Expects columns:
      - timestamp (datetime)
      - src_ip (string)
      - action (string)
    """
    required = {"timestamp", "src_ip", "action", "traffic_direction"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns for repeated denies detection: {missing}")

    work = df.copy()
    work = work.dropna(subset=["timestamp", "src_ip", "action"])

    #Only analyse denied traffic events
    denies = work[work["action"].astype(str).str.lower() == "deny"].copy()
    if denies.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "traffic_direction", "deny_count"])

    #Group deny events by time window, source IP, and traffic direction
    denies = denies.set_index("timestamp").sort_index()

    group_cols = [
        pd.Grouper(freq=f"{window_minutes}min"),
        "src_ip",
        "traffic_direction",
    ]  
    
    grouped = (
        denies.groupby(group_cols)
        .size()
        .reset_index(name="deny_count")
        .rename(columns={"timestamp": "window_start"})
    )

    #Return only IPs exceeding the configured threshold
    flagged = grouped[grouped["deny_count"] >= threshold].copy()
    return flagged.sort_values(["deny_count", "src_ip"], ascending=[False, True])


#Counts total traffic events within each time window
def traffic_counts_per_window(
        df: pd.DataFrame,
        window_minutes: int = 1,
    ) -> pd.DataFrame:
        """
        Counts total events per time window.
        Expects: timestamp column (datetime)
        Returns: window_start, event_count
        """
        if "timestamp" not in df.columns:
            raise ValueError("Missing required column: timestamp")

        work = df.dropna(subset=["timestamp"]).copy()
        if work.empty:
            return pd.DataFrame(columns=["window_start", "event_count"])

        work = work.set_index("timestamp").sort_index()

        counts = (
            work.groupby(pd.Grouper(freq=f"{window_minutes}min"))
            .size()
            .reset_index(name="event_count")
            .rename(columns={"timestamp": "window_start"})
        )
        return counts    


#Detects traffic spikes based on fixed thresholds or dynamic median-based thresholds
def detect_traffic_spikes(
    counts_df: pd.DataFrame,
    method: str = "fixed",
    fixed_threshold: int = 100,
    multiplier: float = 3.0,
) -> tuple[pd.DataFrame, int]:
    """
    Flags traffic spikes based on a chosen thresholding method.

    Returns:
      (flagged_df, used_threshold)

    Methods:
      - fixed: uses fixed_threshold
      - median_multiplier: threshold = median(event_count) * multiplier
    """
    required = {"window_start", "event_count"}
    missing = required - set(counts_df.columns)
    if missing:
        raise ValueError(f"Missing required columns for spike detection: {missing}")

    if counts_df.empty:
        return (pd.DataFrame(columns=["window_start", "event_count"]), 0)

    method = (method or "fixed").strip().lower()

    if method == "median_multiplier":
        med = float(counts_df["event_count"].median())
        used_threshold = int(max(1, round(med * float(multiplier))))
    else:
        used_threshold = int(fixed_threshold)

    flagged = counts_df[counts_df["event_count"] >= used_threshold].copy()
    flagged = flagged.sort_values("event_count", ascending=False)

    return (flagged, used_threshold)


#Detects potential port scanning by identifying many distinct destination ports from one source IP
def detect_port_scans(
    df: pd.DataFrame,
    window_minutes: int = 1,
    unique_ports_threshold: int = 20,
    action_filter: str | None = None,
) -> pd.DataFrame:
    """
    Flags potential port scans: a src_ip contacting many distinct dst_ports within a time window.

    Expects columns:
      - timestamp (datetime)
      - src_ip (string)
      - dst_port (numeric)
    """
    required = {"timestamp", "src_ip", "dst_port"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns for port scan detection: {missing}")

    work = df.dropna(subset=["timestamp", "src_ip", "dst_port"]).copy()

    #Optional filtering by action type, e.g. only deny events
    if action_filter:
        work = work[work["action"].astype(str).str.lower() == action_filter.lower()]

    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_dst_ports", "dst_ports_list"])

    work = work.set_index("timestamp").sort_index()

    grouped = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])["dst_port"]
        .agg(unique_dst_ports=lambda s: s.nunique(), dst_ports_list=lambda s: sorted(set(s.astype(int).tolist())))
        .reset_index()
        .rename(columns={"timestamp": "window_start"})
    )

    flagged = grouped[grouped["unique_dst_ports"] >= unique_ports_threshold].copy()
    return flagged.sort_values(["unique_dst_ports"], ascending=False)


#Returns the most active source IPs by total number of events
def top_sources_by_events(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "event_count"])

    out = (
        df.groupby("src_ip")
        .size()
        .reset_index(name="event_count")
        .sort_values("event_count", ascending=False)
        .head(top_n)
    )
    return out


#Returns the top source IPs responsible for denied events
def top_denied_sources(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "deny_count"])

    if "action" not in df.columns:
        return pd.DataFrame(columns=["src_ip", "deny_count"])

    denied = df[df["action"].astype(str).str.lower() == "deny"]
    if denied.empty:
        return pd.DataFrame(columns=["src_ip", "deny_count"])

    out = (
        denied.groupby("src_ip")
        .size()
        .reset_index(name="deny_count")
        .sort_values("deny_count", ascending=False)
        .head(top_n)
    )
    return out


#Returns the most frequently targeted destination ports
def top_targeted_ports(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["dst_port", "hit_count"])

    if "dst_port" not in df.columns:
        return pd.DataFrame(columns=["dst_port", "hit_count"])

    out = (
        df.groupby("dst_port")
        .size()
        .reset_index(name="hit_count")
        .sort_values("hit_count", ascending=False)
        .head(top_n)
    )
    return out


#Returns the most frequently contacted destination hosts
def top_destination_hosts(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["dst_ip", "hit_count"])

    if "dst_ip" not in df.columns:
        return pd.DataFrame(columns=["dst_ip", "hit_count"])

    out = (
        df.groupby("dst_ip")
        .size()
        .reset_index(name="hit_count")
        .sort_values("hit_count", ascending=False)
        .head(top_n)
    )
    return out


#Defines internal/private datacenter IP ranges used for traffic classification
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


#Detects east-west lateral movement by identifying internal hosts contacting many internal destinations
def detect_lateral_movement(
    df: pd.DataFrame,
    window_minutes: int = 5,
    unique_internal_dsts_threshold: int = 20,
    action_filter: str | None = None,
) -> pd.DataFrame:
    """
    Flags potential lateral movement: an internal src_ip contacting many internal dst_ip
    (east-west fan-out) within a time window.
    """
    required = {"timestamp", "src_ip", "dst_ip", "traffic_direction"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns for lateral movement detection: {missing}")

    work = df.dropna(subset=["timestamp", "src_ip", "dst_ip"]).copy()

    #Focus only on internal-to-internal communication
    work = work[work["traffic_direction"] == "east_west"]

    if action_filter:
        if "action" not in work.columns:
            raise ValueError("action_filter was provided but 'action' column is missing")
        work = work[work["action"].str.lower() == action_filter.lower()]

    if work.empty:
        return pd.DataFrame(
            columns=["window_start", "src_ip", "unique_internal_dsts", "dst_hosts_list", "event_count"]
        )

    work = work.set_index("timestamp").sort_index()

    grouped = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])["dst_ip"]
        .agg(
            unique_internal_dsts=lambda s: s.nunique(),
            dst_hosts_list=lambda s: sorted(set(s.astype(str).tolist())),
            event_count="size",
        )
        .reset_index()
        .rename(columns={"timestamp": "window_start"})
    )

    flagged = grouped[grouped["unique_internal_dsts"] >= unique_internal_dsts_threshold].copy()
    return flagged.sort_values(["unique_internal_dsts", "event_count"], ascending=[False, False])


#Detects repeated failed authentication attempts
def detect_auth_failed_logins(
    df: pd.DataFrame,
    window_minutes: int = 5,
    threshold: int = 5,
    group_by: str = "src_ip",
    fail_values: tuple[str, ...] = ("fail", "failed", "deny", "denied"),
) -> pd.DataFrame:
    """
    Detect repeated failed logins in auth logs.
    """
    required = {"timestamp", "action"}
    missing = required - set(df.columns)
    if missing:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count"])

    if group_by not in df.columns:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count"])

    work = df.dropna(subset=["timestamp", "action", group_by]).copy()
    if work.empty:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count"])

    actions = work["action"].astype(str).str.lower()
    work = work[actions.isin([v.lower() for v in fail_values])]
    if work.empty:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count"])

    work = work.set_index("timestamp").sort_index()

    out = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), group_by])
        .size()
        .reset_index(name="fail_count")
        .rename(columns={"timestamp": "window_start", group_by: "entity"})
    )

    out = out[out["fail_count"] >= threshold].copy()
    return out.sort_values(["fail_count"], ascending=False)


#Detects bursts of IDS alerts from the same source IP
def detect_ids_alert_burst(
    df: pd.DataFrame,
    window_minutes: int = 5,
    threshold: int = 3,
    severity_filter: tuple[str, ...] = ("high", "critical"),
) -> pd.DataFrame:
    """
    Detect IDS alert bursts from the same src_ip within a time window.
    """
    required = {"timestamp", "src_ip"}
    missing = required - set(df.columns)
    if missing:
        return pd.DataFrame(columns=["window_start", "src_ip", "alert_count", "top_signatures"])

    work = df.dropna(subset=["timestamp", "src_ip"]).copy()
    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "alert_count", "top_signatures"])

    #Optional severity filtering to focus on higher-priority alerts
    if "severity" in work.columns and severity_filter:
        sev = work["severity"].astype(str).str.lower()
        allowed = {s.lower() for s in severity_filter}
        work = work[sev.isin(allowed)]

    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "alert_count", "top_signatures"])

    work = work.set_index("timestamp").sort_index()

    def _top_sigs(x: pd.Series) -> list[str]:
        if "signature" not in work.columns:
            return []
        counts = x.astype(str).value_counts()
        return counts.head(5).index.tolist()

    if "signature" in work.columns:
        grouped = (
            work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])["signature"]
            .agg(alert_count="size", top_signatures=_top_sigs)
            .reset_index()
            .rename(columns={"timestamp": "window_start"})
        )
    else:
        grouped = (
            work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])
            .size()
            .reset_index(name="alert_count")
            .assign(top_signatures=[[]] * 0)
            .rename(columns={"timestamp": "window_start"})
        )
        grouped["top_signatures"] = [[] for _ in range(len(grouped))]

    flagged = grouped[grouped["alert_count"] >= threshold].copy()
    return flagged.sort_values(["alert_count"], ascending=False)


#Checks whether an IP address belongs to a private/internal network
def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in INTERNAL_NETWORKS)
    except Exception:
        return False


#Enriches logs by classifying traffic direction as east-west, north-south, or external-external
def add_traffic_direction(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds columns:
      - src_is_internal
      - dst_is_internal
      - traffic_direction: east_west / north_south / external_external
    """
    required = {"src_ip", "dst_ip"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns for traffic direction: {missing}")

    out = df.copy()
    out["src_is_internal"] = out["src_ip"].astype(str).apply(is_internal_ip)
    out["dst_is_internal"] = out["dst_ip"].astype(str).apply(is_internal_ip)

    def classify(row) -> str:
        if row["src_is_internal"] and row["dst_is_internal"]:
            return "east_west"
        if row["src_is_internal"] != row["dst_is_internal"]:
            return "north_south"
        return "external_external"

    out["traffic_direction"] = out.apply(classify, axis=1)
    return out


#Detects successful logins that occur after multiple failures in the same time window
def detect_auth_success_after_failures(
    df: pd.DataFrame,
    window_minutes: int = 5,
    fail_threshold: int = 5,
    group_by: str = "src_ip",
    fail_values: tuple[str, ...] = ("fail", "failed", "deny", "denied"),
    success_values: tuple[str, ...] = ("success", "ok", "allow", "allowed"),
) -> pd.DataFrame:
    """
    Detect: multiple failures followed by >=1 success in the same time window.
    """
    required = {"timestamp", "action"}
    if not required.issubset(df.columns) or group_by not in df.columns:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count", "success_count"])

    work = df.dropna(subset=["timestamp", "action", group_by]).copy()
    if work.empty:
        return pd.DataFrame(columns=["window_start", "entity", "fail_count", "success_count"])

    work["action_norm"] = work["action"].astype(str).str.lower().str.strip()
    fail_set = {v.lower() for v in fail_values}
    success_set = {v.lower() for v in success_values}

    work["is_fail"] = work["action_norm"].isin(fail_set).astype(int)
    work["is_success"] = work["action_norm"].isin(success_set).astype(int)

    work = work.set_index("timestamp").sort_index()

    grouped = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), group_by])[["is_fail", "is_success"]]
        .sum()
        .reset_index()
        .rename(columns={
            "timestamp": "window_start",
            group_by: "entity",
            "is_fail": "fail_count",
            "is_success": "success_count"
        })
    )

    flagged = grouped[(grouped["fail_count"] >= fail_threshold) & (grouped["success_count"] >= 1)].copy()
    return flagged.sort_values(["fail_count", "success_count"], ascending=False)


#Detects exfiltration-style outbound traffic from internal to external destinations
def detect_exfiltration_outbound(
    df: pd.DataFrame,
    window_minutes: int = 5,
    unique_external_dsts_threshold: int = 20,
    event_count_threshold: int = 100,
    action_filter: str | None = "allow",
) -> pd.DataFrame:
    """
    Exfiltration-style outbound anomaly:
      internal src -> external dst with high fan-out and/or high volume.
    """
    required = {"timestamp", "src_ip", "dst_ip", "src_is_internal", "dst_is_internal"}
    if not required.issubset(df.columns):
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_external_dsts", "dst_ips_list", "event_count"])

    work = df.dropna(subset=["timestamp", "src_ip", "dst_ip"]).copy()
    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_external_dsts", "dst_ips_list", "event_count"])

    #Focus on internal source hosts contacting external destinations
    work = work[(work["src_is_internal"] == True) & (work["dst_is_internal"] == False)]

    if action_filter and "action" in work.columns:
        work = work[work["action"].astype(str).str.lower().str.strip() == str(action_filter).lower()]

    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_external_dsts", "dst_ips_list", "event_count"])

    work = work.set_index("timestamp").sort_index()

    def _dst_list(s: pd.Series) -> list[str]:
        return s.astype(str).value_counts().head(20).index.tolist()

    grouped = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])["dst_ip"]
        .agg(event_count="size", unique_external_dsts=pd.Series.nunique, dst_ips_list=_dst_list)
        .reset_index()
        .rename(columns={"timestamp": "window_start"})
    )

    flagged = grouped[
        (grouped["unique_external_dsts"] >= unique_external_dsts_threshold)
        | (grouped["event_count"] >= event_count_threshold)
    ].copy()

    return flagged.sort_values(["unique_external_dsts", "event_count"], ascending=False)


#Detects unusual DNS activity based on many unique domains or high query volume
def detect_dns_domain_spike(
    df: pd.DataFrame,
    window_minutes: int = 5,
    unique_domains_threshold: int = 30,
    total_queries_threshold: int = 100,
    domain_col: str = "dns_query",
) -> pd.DataFrame:
    """
    DNS anomaly: internal host querying many unique domains.
    """
    required = {"timestamp", "src_ip", domain_col}
    if not required.issubset(df.columns):
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_domains", "domains_list", "query_count"])

    work = df.dropna(subset=["timestamp", "src_ip", domain_col]).copy()
    if work.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "unique_domains", "domains_list", "query_count"])

    if "src_is_internal" in work.columns:
        work = work[work["src_is_internal"] == True]

    work[domain_col] = work[domain_col].astype(str).str.lower().str.strip()
    work = work.set_index("timestamp").sort_index()

    def _domain_list(s: pd.Series) -> list[str]:
        return s.value_counts().head(20).index.tolist()

    grouped = (
        work.groupby([pd.Grouper(freq=f"{window_minutes}min"), "src_ip"])[domain_col]
        .agg(query_count="size", unique_domains=pd.Series.nunique, domains_list=_domain_list)
        .reset_index()
        .rename(columns={"timestamp": "window_start"})
    )

    flagged = grouped[
        (grouped["unique_domains"] >= unique_domains_threshold)
        | (grouped["query_count"] >= total_queries_threshold)
    ].copy()

    return flagged.sort_values(["unique_domains", "query_count"], ascending=False)


#Detects successful privileged account activity, especially from external sources
def detect_auth_privileged_activity(
    df: pd.DataFrame,
    window_minutes: int = 10,
    privileged_usernames=None,
    privileged_patterns=None,
    external_only: bool = True,
):
    if privileged_usernames is None:
        privileged_usernames = []
    if privileged_patterns is None:
        privileged_patterns = []

    required = {"timestamp", "username", "src_ip", "action"}
    if not required.issubset(df.columns):
        return pd.DataFrame()

    work = df.copy()

    #Only consider successful logins
    success_mask = work["action"].astype(str).str.lower().isin(["success", "ok", "allow", "allowed"])
    work = work[success_mask]

    if work.empty:
        return pd.DataFrame()

    #Optionally filter to external logins only
    if external_only:
        work = work[~work["src_ip"].astype(str).apply(is_internal_ip)]
        if work.empty:
            return pd.DataFrame()

    priv_set = {str(u).lower().strip() for u in privileged_usernames}
    patterns = [re.compile(p, re.IGNORECASE) for p in privileged_patterns]

    def is_priv(u):
        u = str(u).strip()
        if u.lower() in priv_set:
            return True
        return any(p.search(u) for p in patterns)

    work = work[work["username"].astype(str).apply(is_priv)]

    if work.empty:
        return pd.DataFrame()

    if "dst_ip" not in work.columns:
        work["dst_ip"] = pd.NA

    work = work.set_index("timestamp").sort_index()

    grouped = (
        work.groupby([
            pd.Grouper(freq=f"{window_minutes}min"),
            "username",
            "src_ip",
            "dst_ip"
        ])
        .size()
        .reset_index(name="event_count")
        .rename(columns={"timestamp": "window_start"})
    )

    return grouped


#Detects authentication-based lateral movement by tracking users accessing multiple internal hosts
def detect_auth_lateral_movement(
    df: pd.DataFrame,
    window_minutes: int = 10,
    unique_hosts_threshold: int = 5,
):
    required = {"timestamp", "username", "dst_ip", "action"}
    if not required.issubset(df.columns):
        return pd.DataFrame()

    work = df.copy()

    success_mask = work["action"].astype(str).str.lower().isin(["success", "ok", "allow", "allowed"])
    work = work[success_mask]

    if work.empty:
        return pd.DataFrame()

    work = work[work["dst_ip"].astype(str).apply(is_internal_ip)]

    if work.empty:
        return pd.DataFrame()

    if "src_ip" not in work.columns:
        work["src_ip"] = pd.NA

    work = work.set_index("timestamp").sort_index()

    grouped = (
        work.groupby([
            pd.Grouper(freq=f"{window_minutes}min"),
            "username"
        ])
        .agg(
            event_count=("dst_ip", "size"),
            unique_hosts=("dst_ip", pd.Series.nunique),
            hosts_list=("dst_ip", lambda s: list(set(s.astype(str)))),
            src_ips_list=("src_ip", lambda s: list(set(s.astype(str))))
        )
        .reset_index()
        .rename(columns={"timestamp": "window_start"})
    )

    return grouped[grouped["unique_hosts"] >= unique_hosts_threshold]


#Detects DNS beaconing by looking for regular, repeated queries to the same domain
def detect_dns_beaconing(
    df: pd.DataFrame,
    window_minutes: int = 15,
    min_events: int = 8,
    max_interval_stddev_seconds: float = 3.0,
    min_mean_interval_seconds: float = 10.0,
    max_mean_interval_seconds: float = 3600.0,
):
    required = {"timestamp", "src_ip", "dns_query"}
    if not required.issubset(df.columns):
        return pd.DataFrame()

    work = df.copy()

    if "src_is_internal" in work.columns:
        work = work[work["src_is_internal"] == True]

    if work.empty:
        return pd.DataFrame()

    work = work.set_index("timestamp").sort_index()

    rows = []

    #Group by time window, source IP, and queried domain to look for regular intervals
    for (window, src, domain), g in work.groupby([
        pd.Grouper(freq=f"{window_minutes}min"),
        "src_ip",
        "dns_query"
    ]):
        times = g.index.sort_values()
        if len(times) < min_events:
            continue

        intervals = times.to_series().diff().dropna().dt.total_seconds()
        if intervals.empty:
            continue

        mean_i = intervals.mean()
        std_i = intervals.std(ddof=0)

        #Beaconing tends to have low variance and regular timing
        if (
            min_mean_interval_seconds <= mean_i <= max_mean_interval_seconds
            and std_i <= max_interval_stddev_seconds
        ):
            rows.append({
                "window_start": window,
                "src_ip": src,
                "domain": domain,
                "event_count": len(times),
                "mean_interval_sec": round(mean_i, 3),
                "std_interval_sec": round(std_i, 3),
            })

    return pd.DataFrame(rows)
from __future__ import annotations

from pathlib import Path
import yaml
import pandas as pd

from parser import load_csv_log, DEFAULT_SCHEMA
from report import ensure_dir, save_dataframe
from detectors import add_traffic_direction, top_sources_by_events

from pipelines.firewall_pipeline import run_firewall_pipeline
from pipelines.auth_pipeline import run_auth_pipeline
from pipelines.ids_pipeline import run_ids_pipeline
from pipelines.dns_pipeline import run_dns_pipeline


#Applies global allowlists to remove trusted or expected events before analysis
def apply_allowlists(df: pd.DataFrame, allow_cfg: dict):
    """
    Removes rows matching allowlisted src_ips and/or dst_ports.

    Returns:
        filtered_df,
        summary_df (counts of removed events)
    """
    if df is None or df.empty:
        return df, pd.DataFrame(columns=["type", "value", "removed_events"])

    allow_cfg = allow_cfg or {}
    src_ips = set(str(x).strip() for x in (allow_cfg.get("src_ips") or []) if str(x).strip())
    dst_ports = set(str(p).strip() for p in (allow_cfg.get("dst_ports") or []) if str(p).strip())

    summary_rows = []
    work = df.copy()

    #Remove allowlisted source IPs and track how many events were filtered
    if src_ips and "src_ip" in work.columns:
        for ip in src_ips:
            count = (work["src_ip"].astype(str) == ip).sum()
            if count > 0:
                summary_rows.append({"type": "src_ip", "value": ip, "removed_events": int(count)})
        work = work[~work["src_ip"].astype(str).isin(src_ips)]

    #Remove allowlisted destination ports and track filtered events
    if dst_ports and "dst_port" in work.columns:
        for port in dst_ports:
            count = (work["dst_port"].astype(str) == port).sum()
            if count > 0:
                summary_rows.append({"type": "dst_port", "value": port, "removed_events": int(count)})
        work = work[~work["dst_port"].astype(str).isin(dst_ports)]

    summary_df = pd.DataFrame(summary_rows, columns=["type", "value", "removed_events"])
    return work, summary_df


#Loads log inputs defined in config.yaml and supports both multi-source and legacy single-file mode
def _load_inputs(cfg: dict, project_root: Path) -> pd.DataFrame:
    """
    Multi-source mode: uses sources + inputs from config.yaml.
    Falls back to legacy single-file mode if inputs/sources are not present.
    """
    schema = cfg.get("schema", DEFAULT_SCHEMA)

    #Multi-source mode for handling multiple log files and event types
    if "inputs" in cfg and "sources" in cfg:
        sources = cfg.get("sources", {})
        inputs = cfg.get("inputs", [])
        if not inputs:
            raise ValueError("config.yaml has 'inputs' but it's empty.")

        dfs: list[pd.DataFrame] = []
        for item in inputs:
            rel_path = item["path"]
            source_key = item["source"]

            if source_key not in sources:
                raise ValueError(f"Unknown source '{source_key}'. Define it under config.yaml -> sources:")

            field_map = sources[source_key].get("fields", {})
            event_type = sources[source_key].get("event_type", source_key)
            strict = bool(sources[source_key].get("strict", False))

            log_path = project_root / rel_path
            parsed = load_csv_log(
                log_path,
                field_map=field_map,
                source_name=event_type,
                schema=schema,
                strict=strict,
            )
            dfs.append(parsed.df)

        return pd.concat(dfs, ignore_index=True)

    #Fallback legacy mode for a single firewall log file
    data_dir = project_root / "data"
    log_path = data_dir / "firewall.csv"
    field_map = cfg["fields"]
    parsed = load_csv_log(log_path, field_map=field_map, source_name="firewall", schema=schema, strict=True)
    return parsed.df


#Converts a threshold breach into a simple severity level
def _severity(value: float, threshold: float) -> str:
    if threshold <= 0:
        return "low"
    ratio = value / threshold
    if ratio >= 2.0:
        return "high"
    if ratio >= 1.25:
        return "medium"
    return "low"


#Builds unified firewall alert records from firewall pipeline outputs
def _alerts_from_firewall(fw_results: dict, cfg: dict) -> pd.DataFrame:
    rows = []

    denies_th = int(cfg.get("thresholds", {}).get("repeated_denies_count", 10))
    scan_th = int(cfg.get("thresholds", {}).get("port_scan_unique_ports", 20))
    lateral_th = int(cfg.get("rules", {}).get("lateral_movement", {}).get("unique_internal_dsts", 20))

    ex_cfg = cfg.get("rules", {}).get("exfiltration_outbound", {})
    ex_unique_th = int(ex_cfg.get("unique_external_dsts_threshold", 20))
    ex_events_th = int(ex_cfg.get("event_count_threshold", 100))

    flagged_denies = fw_results.get("denies", pd.DataFrame())
    flagged_scans = fw_results.get("scans", pd.DataFrame())
    flagged_lateral = fw_results.get("lateral", pd.DataFrame())
    flagged_exfil = fw_results.get("exfil", pd.DataFrame())

    #Repeated deny alerts
    if not flagged_denies.empty:
        for _, r in flagged_denies.iterrows():
            deny_count = int(r.get("deny_count", 0))
            rows.append({
                "event_type": "firewall",
                "alert_type": "repeated_denies",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": r.get("traffic_direction"),
                "severity": _severity(deny_count, denies_th),
                "details": f"{deny_count} denies in {r.get('traffic_direction')} traffic",
            })

    #Port scan alerts
    if not flagged_scans.empty:
        for _, r in flagged_scans.iterrows():
            unique_ports = int(r.get("unique_dst_ports", 0))
            rows.append({
                "event_type": "firewall",
                "alert_type": "port_scan",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": None,
                "severity": _severity(unique_ports, scan_th),
                "details": f"{unique_ports} unique dst ports scanned: {r.get('dst_ports_list')}",
            })

    #Lateral movement alerts
    if not flagged_lateral.empty:
        for _, r in flagged_lateral.iterrows():
            unique_hosts = int(r.get("unique_internal_dsts", 0))
            rows.append({
                "event_type": "firewall",
                "alert_type": "lateral_movement",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": "east_west",
                "severity": _severity(unique_hosts, lateral_th),
                "details": f"{unique_hosts} internal hosts contacted: {r.get('dst_hosts_list')}",
            })

    #Outbound exfiltration-style alerts
    if not flagged_exfil.empty:
        for _, r in flagged_exfil.iterrows():
            uniq = int(r.get("unique_external_dsts", 0))
            evc = int(r.get("event_count", 0))
            sev = _severity(max(uniq / max(ex_unique_th, 1), evc / max(ex_events_th, 1)), 1.25)
            rows.append({
                "event_type": "firewall",
                "alert_type": "exfiltration_outbound",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": "north_south",
                "severity": sev,
                "details": f"{uniq} unique external dsts; {evc} events; examples={r.get('dst_ips_list')}",
            })

    return pd.DataFrame(rows, columns=[
        "event_type", "alert_type", "window_start", "src_ip",
        "traffic_direction", "severity", "details"
    ])


#Builds unified authentication alert records from auth pipeline outputs
def _alerts_from_auth(auth_results: dict, cfg: dict) -> pd.DataFrame:
    rows = []

    fail_cfg = cfg.get("rules", {}).get("auth_failed_logins", {})
    fail_th = int(fail_cfg.get("threshold", 5))

    saf_cfg = cfg.get("rules", {}).get("auth_success_after_failures", {})
    saf_fail_th = int(saf_cfg.get("fail_threshold", 5))

    flagged_failed = auth_results.get("failed", pd.DataFrame())
    flagged_saf = auth_results.get("success_after_fail", pd.DataFrame())
    flagged_priv = auth_results.get("privileged", pd.DataFrame())
    flagged_lat = auth_results.get("lateral", pd.DataFrame())

    #Failed login alerts
    if not flagged_failed.empty:
        for _, r in flagged_failed.iterrows():
            count = int(r.get("fail_count", 0))
            entity = r.get("entity")
            rows.append({
                "event_type": "auth",
                "alert_type": "failed_logins",
                "window_start": r.get("window_start"),
                "src_ip": entity if entity and "." in str(entity) else None,
                "traffic_direction": None,
                "severity": _severity(count, fail_th),
                "details": f"{count} failed logins for entity={entity}",
            })

    #Success after multiple failures alerts
    if not flagged_saf.empty:
        for _, r in flagged_saf.iterrows():
            fails = int(r.get("fail_count", 0))
            succ = int(r.get("success_count", 0))
            entity = r.get("entity")
            rows.append({
                "event_type": "auth",
                "alert_type": "success_after_failures",
                "window_start": r.get("window_start"),
                "src_ip": entity if entity and "." in str(entity) else None,
                "traffic_direction": None,
                "severity": _severity(fails, saf_fail_th),
                "details": f"{fails} fails then {succ} success for entity={entity}",
            })
    
    #Privileged activity alerts
    if not flagged_priv.empty:
        for _, r in flagged_priv.iterrows():
            rows.append({
                "event_type": "auth",
                "alert_type": "privileged_activity",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": None,
                "severity": "high",
                "details": f"Privileged login user={r.get('username')} src={r.get('src_ip')} dst={r.get('dst_ip')}",
            })

    #Authentication-based lateral movement alerts
    if not flagged_lat.empty:
        for _, r in flagged_lat.iterrows():
            src_ips = r.get("src_ips_list") or []
            src_ip = src_ips[0] if isinstance(src_ips, list) and len(src_ips) > 0 else None

            rows.append({
                "event_type": "auth",
                "alert_type": "auth_lateral_movement",
                "window_start": r.get("window_start"),
                "src_ip": src_ip,
                "traffic_direction": "east_west",
                "severity": "high",
                "details": f"user={r.get('username')} touched {r.get('unique_hosts')} hosts",
            })
    
    return pd.DataFrame(rows, columns=[
        "event_type", "alert_type", "window_start", "src_ip",
        "traffic_direction", "severity", "details"
    ])


#Builds unified IDS alert records from IDS pipeline outputs
def _alerts_from_ids(ids_results: dict, cfg: dict) -> pd.DataFrame:
    rows = []

    ids_cfg = cfg.get("rules", {}).get("ids_burst", {})
    ids_th = int(ids_cfg.get("threshold", 3))

    flagged = ids_results.get("ids", pd.DataFrame())
    if not flagged.empty:
        for _, r in flagged.iterrows():
            count = int(r.get("alert_count", 0))
            rows.append({
                "event_type": "ids",
                "alert_type": "ids_alert_burst",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": None,
                "severity": _severity(count, ids_th),
                "details": f"{count} IDS alerts; top_signatures={r.get('top_signatures')}",
            })

    return pd.DataFrame(rows, columns=[
        "event_type", "alert_type", "window_start", "src_ip",
        "traffic_direction", "severity", "details"
    ])


#Builds unified DNS alert records from DNS pipeline outputs
def _alerts_from_dns(dns_results: dict, cfg: dict) -> pd.DataFrame:
    rows = []

    dns_cfg = cfg.get("rules", {}).get("dns_domain_spike", {})
    uniq_th = int(dns_cfg.get("unique_domains_threshold", 30))

    flagged = dns_results.get("dns", pd.DataFrame())
    flagged_beacon = dns_results.get("beacon", pd.DataFrame())

    #DNS domain spike alerts
    if not flagged.empty:
        for _, r in flagged.iterrows():
            uniq = int(r.get("unique_domains", 0))
            rows.append({
                "event_type": "dns",
                "alert_type": "dns_domain_spike",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": None,
                "severity": _severity(uniq, uniq_th),
                "details": f"{uniq} unique domains; examples={r.get('domains_list')}",
            })

    #DNS beaconing alerts
    if not flagged_beacon.empty:
        for _, r in flagged_beacon.iterrows():
            rows.append({
                "event_type": "dns",
                "alert_type": "dns_beaconing",
                "window_start": r.get("window_start"),
                "src_ip": r.get("src_ip"),
                "traffic_direction": None,
                "severity": "high",
                "details": f"Beaconing domain={r.get('domain')} events={r.get('event_count')}",
            })    

    return pd.DataFrame(rows, columns=[
        "event_type", "alert_type", "window_start", "src_ip",
        "traffic_direction", "severity", "details"
    ])


#Main entry point for the full analysis workflow
def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    config_path = project_root / "config.yaml"
    out_dir = ensure_dir(project_root / "outputs")

    #Create output subfolders for each log source and global summaries
    global_dir = ensure_dir(out_dir / "global")
    firewall_dir = ensure_dir(out_dir / "firewall")
    auth_dir = ensure_dir(out_dir / "auth")
    ids_dir = ensure_dir(out_dir / "ids")
    dns_dir = ensure_dir(out_dir / "dns")

    if not config_path.exists():
        raise FileNotFoundError(f"Missing config.yaml at: {config_path}")

    #Load configuration settings
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    #Load and combine all configured log inputs
    df_all = _load_inputs(cfg, project_root)

    #Filter trusted/allowlisted events before analysis
    df_all, allow_summary = apply_allowlists(df_all, cfg.get("allowlists", {}))
    if not allow_summary.empty:
        print("\nFiltered by allowlists (removed events):")
        print(allow_summary)
        save_dataframe(allow_summary, global_dir / "allowlist_summary.csv")

    if df_all.empty:
        print("No events to analyse after allowlists. Exiting.")
        return

    #Enrich logs with traffic direction labels (e.g. north-south / east-west)
    df_all = add_traffic_direction(df_all)

    #Save combined normalised dataset
    save_dataframe(df_all, global_dir / "normalised_logs.csv")

    #Split combined dataset into separate source-specific dataframes
    df_firewall = df_all[df_all["event_type"] == "firewall"].copy()
    df_auth = df_all[df_all["event_type"] == "auth"].copy()
    df_ids = df_all[df_all["event_type"] == "ids"].copy()
    df_dns = df_all[df_all["event_type"] == "dns"].copy()

    #Save source-specific normalised outputs
    save_dataframe(df_firewall, firewall_dir / "normalised_firewall.csv")
    save_dataframe(df_auth, auth_dir / "normalised_auth.csv")
    save_dataframe(df_ids, ids_dir / "normalised_ids.csv")
    save_dataframe(df_dns, dns_dir / "normalised_dns.csv")

    #Run individual analysis pipelines for each log type
    fw_results = run_firewall_pipeline(df_firewall, cfg, firewall_dir)
    auth_results = run_auth_pipeline(df_auth, cfg, auth_dir)
    ids_results = run_ids_pipeline(df_ids, cfg, ids_dir)
    dns_results = run_dns_pipeline(df_dns, cfg, dns_dir)

    #Convert pipeline outputs into one unified alerts summary
    alerts_fw = _alerts_from_firewall(fw_results, cfg)
    alerts_auth = _alerts_from_auth(auth_results, cfg)
    alerts_ids = _alerts_from_ids(ids_results, cfg)
    alerts_dns = _alerts_from_dns(dns_results, cfg)

    alert_frames = [alerts_fw, alerts_auth, alerts_ids, alerts_dns]

    #Remove empty dataframes before concatenation
    alert_frames = [df for df in alert_frames if df is not None and not df.empty]

    if alert_frames:
        alerts_summary = pd.concat(alert_frames, ignore_index=True)
    else:
        alerts_summary = pd.DataFrame(columns=[
            "event_type", "alert_type", "window_start",
            "src_ip", "traffic_direction", "severity", "details"
        ])

    #Sort alerts by severity and time for clearer reporting
    if not alerts_summary.empty:
        severity_order = {"high": 0, "medium": 1, "low": 2}
        alerts_summary["severity_rank"] = alerts_summary["severity"].map(severity_order).fillna(3).astype(int)
        alerts_summary = (
            alerts_summary.sort_values(["severity_rank", "window_start"], ascending=[True, True])
            .drop(columns=["severity_rank"])
        )

    

    #Save final alert summary and top source statistics
    save_dataframe(alerts_summary, global_dir / "alerts_summary.csv")

    top_n = int(cfg.get("summaries", {}).get("top_n", 10))
    save_dataframe(top_sources_by_events(df_all, top_n=top_n), global_dir / "top_sources_by_events.csv")


if __name__ == "__main__":
    main()
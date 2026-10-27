from __future__ import annotations
import pandas as pd
from report import save_dataframe, plot_traffic_counts
from detectors import (
    detect_repeated_denies,
    detect_port_scans,
    detect_lateral_movement,
    detect_exfiltration_outbound,
    traffic_counts_per_window,
    detect_traffic_spikes,
    top_denied_sources,
    top_targeted_ports,
    top_destination_hosts,
)


#Runs the firewall analysis pipeline
#This pipeline detects network-based threats such as brute-force attempts,
#port scanning, lateral movement, data exfiltration, and traffic spikes
def run_firewall_pipeline(df_firewall, cfg, firewall_dir):

    #Load detection thresholds from configuration
    fw_threshold_denies = int(cfg.get("thresholds", {}).get("repeated_denies_count", 10))
    fw_port_threshold = int(cfg.get("thresholds", {}).get("port_scan_unique_ports", 20))
    fw_port_action_filter = cfg.get("rules", {}).get("port_scan", {}).get("action_filter")

    fw_lateral_cfg = cfg.get("rules", {}).get("lateral_movement", {})
    fw_lateral_unique = int(fw_lateral_cfg.get("unique_internal_dsts", 20))
    fw_lateral_action_filter = fw_lateral_cfg.get("action_filter")

    ex_cfg = cfg.get("rules", {}).get("exfiltration_outbound", {})
    ex_window = int(ex_cfg.get("window_minutes", 5))
    ex_unique = int(ex_cfg.get("unique_external_dsts_threshold", 20))
    ex_events = int(ex_cfg.get("event_count_threshold", 100))
    ex_action = ex_cfg.get("action_filter", "allow")

    #Load time window configurations for different detection types
    w_brute = int(cfg["windows"]["brute_force_minutes"])
    w_scan = int(cfg["windows"]["portscan_minutes"])
    w_lateral = int(cfg["windows"].get("lateral_minutes", 5))
    w_spike = int(cfg["windows"]["spike_minutes"])

    #Load spike detection configuration
    spike_cfg = cfg.get("rules", {}).get("spike", {})
    spike_method = spike_cfg.get("method", "fixed")
    spike_multiplier = float(spike_cfg.get("multiplier", 3))
    spike_fixed = int(spike_cfg.get("fixed_threshold", 100))

    # --- repeated denies ---
    #Detect repeated deny events which may indicate brute-force or scanning activity
    flagged_denies = detect_repeated_denies(
        df_firewall, window_minutes=w_brute, threshold=fw_threshold_denies
    ) if not df_firewall.empty else pd.DataFrame()

    save_dataframe(flagged_denies, firewall_dir / "flagged_repeated_denies.csv")

    # --- port scans ---
    #Detect sources attempting connections to many different ports
    flagged_scans = detect_port_scans(
        df_firewall,
        window_minutes=w_scan,
        unique_ports_threshold=fw_port_threshold,
        action_filter=fw_port_action_filter,
    ) if not df_firewall.empty else pd.DataFrame()

    save_dataframe(flagged_scans, firewall_dir / "flagged_port_scans.csv")

    # --- lateral movement ---
    #Detect internal hosts communicating with many internal destinations (east-west movement)
    flagged_lateral = detect_lateral_movement(
        df_firewall,
        window_minutes=w_lateral,
        unique_internal_dsts_threshold=fw_lateral_unique,
        action_filter=fw_lateral_action_filter,
    ) if not df_firewall.empty else pd.DataFrame()

    save_dataframe(flagged_lateral, firewall_dir / "flagged_lateral_movement.csv")

    # --- outbound exfil ---
    #Detect possible data exfiltration from internal hosts to external destinations
    flagged_exfil = detect_exfiltration_outbound(
        df_firewall,
        window_minutes=ex_window,
        unique_external_dsts_threshold=ex_unique,
        event_count_threshold=ex_events,
        action_filter=ex_action,
    ) if not df_firewall.empty else pd.DataFrame()

    save_dataframe(flagged_exfil, firewall_dir / "flagged_exfiltration_outbound.csv")

    # --- spikes ---
    #Analyse overall traffic volume and detect sudden spikes
    fw_counts = traffic_counts_per_window(
        df_firewall.dropna(subset=["timestamp"]) if not df_firewall.empty else df_firewall,
        window_minutes=w_spike
    )
    fw_spikes, _ = detect_traffic_spikes(
        fw_counts,
        method=spike_method,
        fixed_threshold=spike_fixed,
        multiplier=spike_multiplier,
    )

    save_dataframe(fw_counts, firewall_dir / "traffic_counts.csv")
    save_dataframe(fw_spikes, firewall_dir / "flagged_spikes.csv")
    plot_traffic_counts(
        fw_counts[["window_start", "event_count"]] if not fw_counts.empty else fw_counts,
        firewall_dir / "traffic_counts.png"
    )


    # --- top summaries ---
    #Generate summary statistics for reporting and dashboard visualisation
    top_n = int(cfg.get("summaries", {}).get("top_n", 10))
    save_dataframe(top_denied_sources(df_firewall, top_n=top_n), firewall_dir / "top_denied_sources.csv")
    save_dataframe(top_targeted_ports(df_firewall, top_n=top_n), firewall_dir / "top_targeted_ports.csv")
    save_dataframe(top_destination_hosts(df_firewall, top_n=top_n), firewall_dir / "top_destination_hosts.csv")

    #Return key results for integration into the global alert system
    return {
        "denies": flagged_denies,
        "scans": flagged_scans,
        "lateral": flagged_lateral,
        "exfil": flagged_exfil,
    }
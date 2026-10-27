from __future__ import annotations
import pandas as pd
from report import save_dataframe, plot_traffic_counts
from detectors import (
    detect_dns_domain_spike,
    detect_dns_beaconing,
    traffic_counts_per_window,
    detect_traffic_spikes,
)


#Runs the DNS analysis pipeline
#Detects abnormal DNS behaviour such as domain spikes, beaconing activity, and traffic spikes
def run_dns_pipeline(df_dns, cfg, dns_dir):
    #Load configuration for DNS domain spike detection
    dns_cfg = cfg.get("rules", {}).get("dns_domain_spike", {})
    dns_window = int(dns_cfg.get("window_minutes", 5))
    dns_unique = int(dns_cfg.get("unique_domains_threshold", 30))
    dns_total = int(dns_cfg.get("total_queries_threshold", 100))

    #Detect hosts querying many unique domains or generating excessive DNS traffic
    flagged_dns = detect_dns_domain_spike(
        df_dns,
        window_minutes=dns_window,
        unique_domains_threshold=dns_unique,
        total_queries_threshold=dns_total,
        domain_col="dns_query",
    ) if not df_dns.empty else pd.DataFrame()

    #Save DNS domain spike detection results
    save_dataframe(flagged_dns, dns_dir / "flagged_dns_domain_spike.csv")

    #Load configuration for DNS beaconing detection
    beacon_cfg = cfg.get("rules", {}).get("dns_beaconing", {})

    #Detect periodic DNS queries that may indicate command-and-control (C2) activity
    flagged_beacon = detect_dns_beaconing(
        df_dns,
        window_minutes=beacon_cfg.get("window_minutes", 15),
        min_events=beacon_cfg.get("min_events", 8),
        max_interval_stddev_seconds=beacon_cfg.get("max_interval_stddev_seconds", 3.0),
        min_mean_interval_seconds=beacon_cfg.get("min_mean_interval_seconds", 10.0),
        max_mean_interval_seconds=beacon_cfg.get("max_mean_interval_seconds", 3600.0),
    ) if not df_dns.empty else pd.DataFrame()

    #Save DNS beaconing detection results
    save_dataframe(flagged_beacon, dns_dir / "flagged_dns_beaconing.csv")


    #Load spike detection configuration for overall DNS traffic
    w_spike = int(cfg["windows"]["spike_minutes"])
    spike_cfg = cfg.get("rules", {}).get("spike", {})
    spike_method = spike_cfg.get("method", "fixed")
    spike_multiplier = float(spike_cfg.get("multiplier", 3))
    spike_fixed = int(spike_cfg.get("fixed_threshold", 100))

    #Generate DNS traffic counts and detect abnormal spikes
    counts = traffic_counts_per_window(df_dns, window_minutes=w_spike)
    spikes, _ = detect_traffic_spikes(counts, method=spike_method,
                                      fixed_threshold=spike_fixed,
                                      multiplier=spike_multiplier)

    #Save traffic summary and visualisation
    save_dataframe(counts, dns_dir / "traffic_counts.csv")
    save_dataframe(spikes, dns_dir / "flagged_spikes.csv")
    plot_traffic_counts(
        counts[["window_start", "event_count"]] if not counts.empty else counts,
        dns_dir / "traffic_counts.png"
    )

    #Return flagged DNS anomalies for use in global alert summary
    return {"dns": flagged_dns, "beacon": flagged_beacon}
from __future__ import annotations
import pandas as pd
from report import save_dataframe, plot_traffic_counts
from detectors import (
    detect_ids_alert_burst,
    traffic_counts_per_window,
    detect_traffic_spikes,
)


#Runs the IDS (Intrusion Detection System) analysis pipeline
#Focuses on identifying bursts of high-severity alerts and abnormal traffic spikes
def run_ids_pipeline(df_ids, cfg, ids_dir):
    #Load IDS burst detection configuration
    ids_cfg = cfg.get("rules", {}).get("ids_burst", {})
    ids_window = int(ids_cfg.get("window_minutes", 5))
    ids_threshold = int(ids_cfg.get("threshold", 3))
    ids_sev = tuple(ids_cfg.get("severity_filter", ["high", "critical"]))

    #Detect bursts of IDS alerts from the same source within a time window
    flagged_ids = detect_ids_alert_burst(
        df_ids,
        window_minutes=ids_window,
        threshold=ids_threshold,
        severity_filter=ids_sev,
    ) if not df_ids.empty else pd.DataFrame()

    #Save IDS alert burst results
    save_dataframe(flagged_ids, ids_dir / "flagged_alert_bursts.csv")

    #Load spike detection configuration for overall IDS activity
    w_spike = int(cfg["windows"]["spike_minutes"])
    spike_cfg = cfg.get("rules", {}).get("spike", {})
    spike_method = spike_cfg.get("method", "fixed")
    spike_multiplier = float(spike_cfg.get("multiplier", 3))
    spike_fixed = int(spike_cfg.get("fixed_threshold", 100))

    #Analyse IDS event volume over time and detect abnormal spikes
    counts = traffic_counts_per_window(df_ids, window_minutes=w_spike)
    spikes, _ = detect_traffic_spikes(counts, method=spike_method,
                                      fixed_threshold=spike_fixed,
                                      multiplier=spike_multiplier)

    #Save IDS traffic summaries and visualisations
    save_dataframe(counts, ids_dir / "traffic_counts.csv")
    save_dataframe(spikes, ids_dir / "flagged_spikes.csv")
    plot_traffic_counts(
        counts[["window_start", "event_count"]] if not counts.empty else counts,
        ids_dir / "traffic_counts.png"
    )

    #Return IDS detection results for global alert aggregation
    return {"ids": flagged_ids}
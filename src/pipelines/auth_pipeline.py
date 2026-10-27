from __future__ import annotations
import pandas as pd
from report import save_dataframe, plot_traffic_counts
from detectors import (
    detect_auth_failed_logins,
    detect_auth_success_after_failures,
    detect_auth_privileged_activity,
    detect_auth_lateral_movement,
    traffic_counts_per_window,
    detect_traffic_spikes,
)


#Runs the full authentication analysis pipeline
#This pipeline detects failed logins, success after failures, privileged account use,
#authentication-based lateral movement, and overall traffic spikes
def run_auth_pipeline(df_auth, cfg, auth_dir):
    #Load configuration for failed login detection
    auth_cfg = cfg.get("rules", {}).get("auth_failed_logins", {})
    auth_window = int(auth_cfg.get("window_minutes", 5))
    auth_threshold = int(auth_cfg.get("threshold", 5))
    auth_group_by = auth_cfg.get("group_by", "src_ip")

    #Detect repeated failed login attempts
    flagged_auth = detect_auth_failed_logins(
        df_auth,
        window_minutes=auth_window,
        threshold=auth_threshold,
        group_by=auth_group_by,
    ) if not df_auth.empty else pd.DataFrame()

    #Save failed login detection results
    save_dataframe(flagged_auth, auth_dir / "flagged_failed_logins.csv")

    #Load configuration for detecting successful logins after repeated failures
    saf_cfg = cfg.get("rules", {}).get("auth_success_after_failures", {})
    saf_window = int(saf_cfg.get("window_minutes", 5))
    saf_fail_threshold = int(saf_cfg.get("fail_threshold", 5))
    saf_group_by = saf_cfg.get("group_by", "src_ip")

    #Detect possible compromise patterns where a success follows multiple failures
    flagged_saf = detect_auth_success_after_failures(
        df_auth,
        window_minutes=saf_window,
        fail_threshold=saf_fail_threshold,
        group_by=saf_group_by,
    ) if not df_auth.empty else pd.DataFrame()

    #Save success-after-failure results
    save_dataframe(flagged_saf, auth_dir / "flagged_success_after_failures.csv")

    #Load configuration for privileged account activity detection
    priv_cfg = (cfg.get("rules", {}) or {}).get("auth_privileged_activity") or {}
    flagged_priv = detect_auth_privileged_activity(
        df_auth,
        window_minutes=priv_cfg.get("window_minutes", 10),
        privileged_usernames=priv_cfg.get("privileged_usernames", []),
        privileged_patterns=priv_cfg.get("privileged_patterns", []),
        external_only=priv_cfg.get("external_only", True),
    ) if not df_auth.empty else pd.DataFrame()

    #Save privileged account detection results
    save_dataframe(flagged_priv, auth_dir / "flagged_privileged_activity.csv")

    #Load configuration for authentication-based lateral movement detection
    lat_cfg = (cfg.get("rules", {}) or {}).get("auth_lateral_movement") or {}
    flagged_lat = detect_auth_lateral_movement(
        df_auth,
        window_minutes=lat_cfg.get("window_minutes", 10),
        unique_hosts_threshold=lat_cfg.get("unique_hosts_threshold", 5),
    ) if not df_auth.empty else pd.DataFrame()

    #Save lateral movement detection results
    save_dataframe(flagged_lat, auth_dir / "flagged_auth_lateral_movement.csv")

    #Load spike detection settings for overall authentication traffic
    w_spike = int(cfg["windows"]["spike_minutes"])
    spike_cfg = cfg.get("rules", {}).get("spike", {})
    spike_method = spike_cfg.get("method", "fixed")
    spike_multiplier = float(spike_cfg.get("multiplier", 3))
    spike_fixed = int(spike_cfg.get("fixed_threshold", 100))

    #Count authentication events per time window and detect spikes
    counts = traffic_counts_per_window(df_auth, window_minutes=w_spike)
    spikes, _ = detect_traffic_spikes(counts, method=spike_method,
                                      fixed_threshold=spike_fixed,
                                      multiplier=spike_multiplier)

    #Save traffic summaries and visualisation outputs
    save_dataframe(counts, auth_dir / "traffic_counts.csv")
    save_dataframe(spikes, auth_dir / "flagged_spikes.csv")
    plot_traffic_counts(
        counts[["window_start", "event_count"]] if not counts.empty else counts,
        auth_dir / "traffic_counts.png"
    )

    #Return key flagged datasets for later summary/alert generation
    return {
        "failed": flagged_auth,
        "success_after_fail": flagged_saf,
        "privileged": flagged_priv,
        "lateral": flagged_lat,
    }
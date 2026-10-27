from __future__ import annotations

from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory
import subprocess
import sys
import pandas as pd
from datetime import datetime

#Define important project directories and file locations
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
DATA_DIR = PROJECT_ROOT / "data"
GENERATORS_DIR = PROJECT_ROOT / "generators"
SRC_DIR = PROJECT_ROOT / "src"

#Global output files used by the dashboard
ALERTS_CSV = OUTPUTS_DIR / "global" / "alerts_summary.csv"
TOP_SOURCES_CSV = OUTPUTS_DIR / "global" / "top_sources_by_events.csv"

#Raw uploaded/generated log file locations
FIREWALL_CSV = DATA_DIR / "firewall.csv"
AUTH_CSV = DATA_DIR / "auth.csv"
IDS_CSV = DATA_DIR / "ids.csv"
DNS_CSV = DATA_DIR / "dns.csv"

#Normalised per-source output files
NORMALISED_FIREWALL_CSV = OUTPUTS_DIR / "firewall" / "normalised_firewall.csv"
NORMALISED_AUTH_CSV = OUTPUTS_DIR / "auth" / "normalised_auth.csv"
NORMALISED_IDS_CSV = OUTPUTS_DIR / "ids" / "normalised_ids.csv"
NORMALISED_DNS_CSV = OUTPUTS_DIR / "dns" / "normalised_dns.csv"

#Restrict which generator scripts can be triggered from the web UI
ALLOWED_GENERATORS = {
    "gen_basic_test_data.py",
    "gen_chain_all.py",
    "gen_chain_ddos_like_spike.py",
    "gen_chain_external_ransomware.py",
    "gen_chain_insider_exfil.py",
}

#Restrict uploaded files to supported log types and filenames
ALLOWED_UPLOADS = {
    "firewall": "firewall.csv",
    "auth": "auth.csv",
    "ids": "ids.csv",
    "dns": "dns.csv",
}

#Initialise Flask app with template and static file locations
app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)


#Runs a Python script (generator or analysis) and captures its output
def run_script(script_path: Path) -> tuple[int, str]:
    if not script_path.exists():
        return 1, f"Script not found: {script_path}"
    try:
        p = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return p.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 1, "Timeout: script took too long."
    except Exception as e:
        return 1, f"Error: {e}"


#Safely reads a CSV file and returns an empty DataFrame if missing or invalid
def safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


#Builds a time-series view of raw log traffic across all source types
#Used for dashboard charts showing event volume over time
def build_raw_traffic_series(interval: str = "5min", points: int = 30) -> dict:
    sources = [
        ("firewall", FIREWALL_CSV, "timestamp"),
        ("auth", AUTH_CSV, "time"),
        ("ids", IDS_CSV, "ts"),
        ("dns", DNS_CSV, "timestamp"),
    ]

    series_map = {}
    full_index = None

    for name, path, ts_col in sources:
        raw = safe_read_csv(path)

        if raw.empty or ts_col not in raw.columns:
            s = pd.Series(dtype="int64")
        else:
            raw = raw.copy()
            raw["dt"] = pd.to_datetime(raw[ts_col], errors="coerce")
            raw = raw.dropna(subset=["dt"])

            if raw.empty:
                s = pd.Series(dtype="int64")
            else:
                raw["bucket"] = raw["dt"].dt.floor(interval)
                s = raw.groupby("bucket").size().sort_index()

        series_map[name] = s

        if not s.empty:
            full_index = s.index if full_index is None else full_index.union(s.index)

    if full_index is None or len(full_index) == 0:
        return {"labels": [], "firewall": [], "auth": [], "ids": [], "dns": []}

    full_index = pd.date_range(full_index.min(), full_index.max(), freq=interval)

    out = {}
    for name in ["firewall", "auth", "ids", "dns"]:
        s = series_map.get(name, pd.Series(dtype="int64"))
        s = s.reindex(full_index, fill_value=0)
        out[name] = s.tail(points).tolist()

    labels_index = full_index[-min(points, len(full_index)):]
    return {
        "labels": [t.strftime("%H:%M") for t in labels_index],
        "firewall": out["firewall"][-len(labels_index):],
        "auth": out["auth"][-len(labels_index):],
        "ids": out["ids"][-len(labels_index):],
        "dns": out["dns"][-len(labels_index):],
    }


#Builds a ranked list of the most active source IPs across all raw logs
def build_top_sources_from_raw_logs(limit: int = 20) -> list[dict]:
    sources = [
        (FIREWALL_CSV, ["src_ip", "source_ip", "ip"]),
        (AUTH_CSV, ["src_ip", "client_ip", "source_ip", "ip"]),
        (IDS_CSV, ["src_ip", "source_ip", "src", "ip"]),
        (DNS_CSV, ["src_ip", "source_ip", "ip"]),
    ]

    counts: dict[str, int] = {}

    for path, candidate_cols in sources:
        df = safe_read_csv(path)
        if df.empty:
            continue

        src_col = next((c for c in candidate_cols if c in df.columns), None)
        if not src_col:
            continue

        series = (
            df[src_col]
            .astype(str)
            .replace(["nan", "None", "NaN"], "")
            .str.strip()
        )
        series = series[series != ""]

        vc = series.value_counts()
        for ip, count in vc.items():
            counts[str(ip)] = counts.get(str(ip), 0) + int(count)

    if not counts:
        return []

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    max_count = ranked[0][1] if ranked else 1

    return [
        {
            "src_ip": ip,
            "count": int(count),
            "pct": round((count / max_count) * 100, 1) if max_count else 0.0,
        }
        for ip, count in ranked
    ]


#Builds the firewall page payload including raw logs, normalised logs,
#alerts, summary metrics, and time-series chart data
def build_firewall_payload() -> dict:
    raw_df = safe_read_csv(FIREWALL_CSV)
    norm_df = safe_read_csv(OUTPUTS_DIR / "firewall" / "normalised_firewall.csv")
    alerts_df = safe_read_csv(ALERTS_CSV)

    if not alerts_df.empty:
        for c in ["event_type", "alert_type", "severity", "details", "window_start", "src_ip"]:
            if c not in alerts_df.columns:
                alerts_df[c] = None

        alerts_df["event_type"] = alerts_df["event_type"].astype(str).str.strip().str.lower()
        alerts_df["severity"] = alerts_df["severity"].astype(str).str.strip().str.lower()
        alerts_df["src_ip"] = alerts_df["src_ip"].astype(str).replace("nan", "").str.strip()
        alerts_df["window_start_dt"] = pd.to_datetime(alerts_df["window_start"], errors="coerce")

        alerts_df = (
            alerts_df[alerts_df["event_type"] == "firewall"]
            .sort_values("window_start_dt", ascending=False)
            .copy()
        )
    else:
        alerts_df = pd.DataFrame()

    raw_columns = list(raw_df.columns) if not raw_df.empty else []
    raw_rows = raw_df.fillna("").head(200).to_dict(orient="records") if not raw_df.empty else []

    normalized_columns = list(norm_df.columns) if not norm_df.empty else []
    normalized_rows = norm_df.fillna("").head(200).to_dict(orient="records") if not norm_df.empty else []

    if not alerts_df.empty:
        alerts_df["time"] = alerts_df["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
        alerts = alerts_df[
            ["time", "alert_type", "src_ip", "severity", "details"]
        ].fillna("").head(200).to_dict(orient="records")
    else:
        alerts = []

    #Build firewall summary metrics such as total logs and allow/deny counts
    action_breakdown = {}
    if not raw_df.empty and "action" in raw_df.columns:
        action_breakdown = (
            raw_df["action"]
            .astype(str)
            .str.strip()
            .str.lower()
            .value_counts()
            .to_dict()
        )

    log_activity = {
        "labels": [],
        "total": [],
        "allow": [],
        "deny": [],
    }

    #Build firewall activity chart grouped into 5-minute buckets
    if not raw_df.empty and "timestamp" in raw_df.columns:
        chart_df = raw_df.copy()
        chart_df["timestamp_dt"] = pd.to_datetime(chart_df["timestamp"], errors="coerce")
        chart_df["action"] = chart_df.get("action", "").astype(str).str.strip().str.lower()
        chart_df = chart_df.dropna(subset=["timestamp_dt"]).copy()

        if not chart_df.empty:
            chart_df["bucket"] = chart_df["timestamp_dt"].dt.floor("5min")

            total_counts = chart_df.groupby("bucket").size().sort_index()
            allow_counts = chart_df[chart_df["action"] == "allow"].groupby("bucket").size()
            deny_counts = chart_df[chart_df["action"] == "deny"].groupby("bucket").size()

            full_idx = pd.date_range(total_counts.index.min(), total_counts.index.max(), freq="5min")

            total_counts = total_counts.reindex(full_idx, fill_value=0)
            allow_counts = allow_counts.reindex(full_idx, fill_value=0)
            deny_counts = deny_counts.reindex(full_idx, fill_value=0)

            log_activity = {
                "labels": [t.strftime("%H:%M") for t in full_idx],
                "total": total_counts.tolist(),
                "allow": allow_counts.tolist(),
                "deny": deny_counts.tolist(),
            }

    return {
        "summary": {
            "total_logs": 0 if raw_df.empty else int(len(raw_df)),
            "raw_count": 0 if raw_df.empty else int(len(raw_df)),
            "alert_count": int(len(alerts)),
            "deny_count": int(action_breakdown.get("deny", 0)),
            "allow_count": int(action_breakdown.get("allow", 0)),
        },
        "raw_columns": raw_columns,
        "raw_rows": raw_rows,
        "normalized_columns": normalized_columns,
        "normalized_rows": normalized_rows,
        "alerts": alerts,
        "log_activity": log_activity,
    }


#Builds the authentication page payload including raw logs, normalised logs,
#alerts, user-related metrics, and activity charts
def build_auth_payload() -> dict:
    raw_df = safe_read_csv(AUTH_CSV)
    norm_df = safe_read_csv(NORMALISED_AUTH_CSV)
    alerts_df = safe_read_csv(ALERTS_CSV)

    if not alerts_df.empty:
        for c in ["event_type", "alert_type", "severity", "details", "window_start", "src_ip", "username", "user"]:
            if c not in alerts_df.columns:
                alerts_df[c] = None

        alerts_df["event_type"] = alerts_df["event_type"].astype(str).str.strip().str.lower()
        alerts_df["severity"] = alerts_df["severity"].astype(str).str.strip().str.lower()
        alerts_df["src_ip"] = alerts_df["src_ip"].astype(str).replace("nan", "").str.strip()

        if "user" not in alerts_df.columns:
            alerts_df["user"] = ""
        alerts_df["user"] = alerts_df["user"].astype(str).replace("nan", "").str.strip()

        if "username" in alerts_df.columns:
            alerts_df["user"] = alerts_df["user"].where(
                alerts_df["user"] != "",
                alerts_df["username"].astype(str).replace("nan", "").str.strip()
            )

        alerts_df["user"] = alerts_df["user"].replace(["None", "none", "nan", "NaN"], "").fillna("")

        if "details" not in alerts_df.columns:
            alerts_df["details"] = ""
        alerts_df["details"] = alerts_df["details"].astype(str).replace("nan", "").str.strip()

        #Extract usernames from alert details if not already present
        def extract_user_from_details(text: str) -> str:
            text = str(text or "")

            patterns = [
                r"user[=: ]+([A-Za-z0-9._@-]+)",
                r"username[=: ]+([A-Za-z0-9._@-]+)",
                r"account[=: ]+([A-Za-z0-9._@-]+)",
                r"for user[=: ]*([A-Za-z0-9._@-]+)",
            ]

            import re
            for pattern in patterns:
                m = re.search(pattern, text, flags=re.IGNORECASE)
                if m:
                    return m.group(1).strip()

            return ""

        alerts_df["user"] = alerts_df.apply(
            lambda row: row["user"] if str(row["user"]).strip() else extract_user_from_details(row["details"]),
            axis=1
        )

        alerts_df["window_start_dt"] = pd.to_datetime(alerts_df["window_start"], errors="coerce")

        alerts_df = (
            alerts_df[alerts_df["event_type"] == "auth"]
            .sort_values("window_start_dt", ascending=False)
            .copy()
        )
    else:
        alerts_df = pd.DataFrame()

    raw_columns = list(raw_df.columns) if not raw_df.empty else []
    raw_rows = raw_df.fillna("").head(200).to_dict(orient="records") if not raw_df.empty else []

    normalized_columns = list(norm_df.columns) if not norm_df.empty else []
    normalized_rows = norm_df.fillna("").head(200).to_dict(orient="records") if not norm_df.empty else []

    if not alerts_df.empty:
        alerts_df["time"] = alerts_df["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
        alerts = alerts_df[
            ["time", "alert_type", "user", "src_ip", "severity", "details"]
        ].fillna("").head(200).to_dict(orient="records")
    else:
        alerts = []

    event_df = norm_df.copy() if not norm_df.empty else raw_df.copy()

    total_logs = 0 if raw_df.empty else int(len(raw_df))
    failed_count = 0
    success_count = 0

    log_activity = {
        "labels": [],
        "total": [],
        "success": [],
        "failed": [],
    }

    #Build authentication charts and summary counts for success/failure activity
    if not event_df.empty:
        if "timestamp" not in event_df.columns:
            event_df["timestamp"] = None

        status_col = None
        for candidate in ["status", "result", "action", "outcome"]:
            if candidate in event_df.columns:
                status_col = candidate
                break

        if status_col is None:
            event_df["status"] = ""
            status_col = "status"

        event_df["timestamp_dt"] = pd.to_datetime(event_df["timestamp"], errors="coerce")
        event_df[status_col] = event_df[status_col].astype(str).str.strip().str.lower()

        failed_mask = event_df[status_col].isin(["fail", "failed", "failure", "denied", "invalid"])
        success_mask = event_df[status_col].isin(["success", "successful", "ok", "accepted", "allow", "allowed"])

        failed_count = int(failed_mask.sum())
        success_count = int(success_mask.sum())

        chart_df = event_df.dropna(subset=["timestamp_dt"]).copy()

        if not chart_df.empty:
            chart_df["bucket"] = chart_df["timestamp_dt"].dt.floor("5min")

            total_counts = chart_df.groupby("bucket").size().sort_index()
            success_counts = chart_df[chart_df[status_col].isin(["success", "successful", "ok", "accepted", "allow", "allowed"])].groupby("bucket").size()
            failed_counts = chart_df[chart_df[status_col].isin(["fail", "failed", "failure", "denied", "invalid"])].groupby("bucket").size()

            full_idx = pd.date_range(total_counts.index.min(), total_counts.index.max(), freq="5min")

            total_counts = total_counts.reindex(full_idx, fill_value=0)
            success_counts = success_counts.reindex(full_idx, fill_value=0)
            failed_counts = failed_counts.reindex(full_idx, fill_value=0)

            log_activity = {
                "labels": [t.strftime("%H:%M") for t in full_idx],
                "total": total_counts.tolist(),
                "success": success_counts.tolist(),
                "failed": failed_counts.tolist(),
            }

    return {
        "summary": {
            "total_logs": total_logs,
            "raw_count": total_logs,
            "alert_count": int(len(alerts)),
            "failed_count": failed_count,
            "success_count": success_count,
        },
        "raw_columns": raw_columns,
        "raw_rows": raw_rows,
        "normalized_columns": normalized_columns,
        "normalized_rows": normalized_rows,
        "alerts": alerts,
        "log_activity": log_activity,
    }


#Builds the IDS page payload with alert summaries, raw/normalised logs,
#and time-series event activity
def build_ids_payload() -> dict:
    raw_df = safe_read_csv(IDS_CSV)
    norm_df = safe_read_csv(NORMALISED_IDS_CSV)
    alerts_df = safe_read_csv(ALERTS_CSV)

    if not alerts_df.empty:
        for c in ["event_type", "alert_type", "severity", "details", "window_start", "src_ip"]:
            if c not in alerts_df.columns:
                alerts_df[c] = None

        alerts_df["event_type"] = alerts_df["event_type"].astype(str).str.strip().str.lower()
        alerts_df["severity"] = alerts_df["severity"].astype(str).str.strip().str.lower()
        alerts_df["src_ip"] = alerts_df["src_ip"].astype(str).replace("nan", "").str.strip()
        alerts_df["window_start_dt"] = pd.to_datetime(alerts_df["window_start"], errors="coerce")

        alerts_df = (
            alerts_df[alerts_df["event_type"].isin(["ids"])]
            .sort_values("window_start_dt", ascending=False)
            .copy()
        )
    else:
        alerts_df = pd.DataFrame()

    raw_columns = list(raw_df.columns) if not raw_df.empty else []
    raw_rows = raw_df.fillna("").head(200).to_dict(orient="records") if not raw_df.empty else []

    normalized_columns = list(norm_df.columns) if not norm_df.empty else []
    normalized_rows = norm_df.fillna("").head(200).to_dict(orient="records") if not norm_df.empty else []

    if not alerts_df.empty:
        alerts_df["time"] = alerts_df["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
        alerts = alerts_df[
            ["time", "alert_type", "src_ip", "severity", "details"]
        ].fillna("").head(200).to_dict(orient="records")
    else:
        alerts = []

    event_df = norm_df.copy() if not norm_df.empty else raw_df.copy()

    total_logs = 0 if raw_df.empty else int(len(raw_df))
    alert_count = int(len(alerts_df)) if not alerts_df.empty else 0
    high_alert_count = int(alerts_df["severity"].isin(["high", "critical"]).sum()) if not alerts_df.empty else 0
    low_alert_count = int(alerts_df["severity"].isin(["low"]).sum()) if not alerts_df.empty else 0

    log_activity = {
        "labels": [],
        "total": [],
        "alert": [],
    }

    #Build IDS chart series using both raw event volume and detected alert volume
    if not event_df.empty:
        ts_col = None
        for candidate in ["timestamp", "ts", "time"]:
            if candidate in event_df.columns:
                ts_col = candidate
                break

        if ts_col is None:
            event_df["timestamp"] = None
            ts_col = "timestamp"

        event_df["timestamp_dt"] = pd.to_datetime(event_df[ts_col], errors="coerce")
        chart_df = event_df.dropna(subset=["timestamp_dt"]).copy()

        if not chart_df.empty:
            chart_df["bucket"] = chart_df["timestamp_dt"].dt.floor("5min")
            total_counts = chart_df.groupby("bucket").size().sort_index()

            if not alerts_df.empty:
                alerts_chart_df = alerts_df.dropna(subset=["window_start_dt"]).copy()
                if not alerts_chart_df.empty:
                    alerts_chart_df["bucket"] = alerts_chart_df["window_start_dt"].dt.floor("5min")
                    alert_counts = alerts_chart_df.groupby("bucket").size().sort_index()
                else:
                    alert_counts = pd.Series(dtype="int64")
            else:
                alert_counts = pd.Series(dtype="int64")

            if not alert_counts.empty:
                full_idx = total_counts.index.union(alert_counts.index).sort_values()
                full_idx = pd.date_range(full_idx.min(), full_idx.max(), freq="5min")
            else:
                full_idx = pd.date_range(total_counts.index.min(), total_counts.index.max(), freq="5min")

            total_counts = total_counts.reindex(full_idx, fill_value=0)
            alert_counts = alert_counts.reindex(full_idx, fill_value=0)

            log_activity = {
                "labels": [t.strftime("%H:%M") for t in full_idx],
                "total": total_counts.tolist(),
                "alert": alert_counts.tolist(),
            }

    return {
        "summary": {
            "total_logs": total_logs,
            "raw_count": total_logs,
            "alert_count": alert_count,
            "high_alert_count": high_alert_count,
            "low_alert_count": low_alert_count,
        },
        "raw_columns": raw_columns,
        "raw_rows": raw_rows,
        "normalized_columns": normalized_columns,
        "normalized_rows": normalized_rows,
        "alerts": alerts,
        "log_activity": log_activity,
    }


#Builds the DNS page payload with raw/normalised logs, DNS alerts,
#and time-series activity for visualisation
def build_dns_payload() -> dict:
    raw_df = safe_read_csv(DNS_CSV)
    norm_df = safe_read_csv(NORMALISED_DNS_CSV)
    alerts_df = safe_read_csv(ALERTS_CSV)

    if not alerts_df.empty:
        for c in ["event_type", "alert_type", "severity", "details", "window_start", "src_ip", "domain", "query", "qname"]:
            if c not in alerts_df.columns:
                alerts_df[c] = None

        alerts_df["event_type"] = alerts_df["event_type"].astype(str).str.strip().str.lower()
        alerts_df["severity"] = alerts_df["severity"].astype(str).str.strip().str.lower()
        alerts_df["src_ip"] = alerts_df["src_ip"].astype(str).replace("nan", "").str.strip()

        if "domain" not in alerts_df.columns:
            alerts_df["domain"] = ""

        alerts_df["domain"] = alerts_df["domain"].astype(str).replace("nan", "").str.strip()

        if "query" in alerts_df.columns:
            alerts_df["domain"] = alerts_df["domain"].where(
                alerts_df["domain"] != "",
                alerts_df["query"].astype(str).replace("nan", "").str.strip()
            )

        if "qname" in alerts_df.columns:
            alerts_df["domain"] = alerts_df["domain"].where(
                alerts_df["domain"] != "",
                alerts_df["qname"].astype(str).replace("nan", "").str.strip()
            )

        alerts_df["window_start_dt"] = pd.to_datetime(alerts_df["window_start"], errors="coerce")

        alerts_df = (
            alerts_df[alerts_df["event_type"] == "dns"]
            .sort_values("window_start_dt", ascending=False)
            .copy()
        )
    else:
        alerts_df = pd.DataFrame()

    raw_columns = list(raw_df.columns) if not raw_df.empty else []
    raw_rows = raw_df.fillna("").head(200).to_dict(orient="records") if not raw_df.empty else []

    normalized_columns = list(norm_df.columns) if not norm_df.empty else []
    normalized_rows = norm_df.fillna("").head(200).to_dict(orient="records") if not norm_df.empty else []

    if not alerts_df.empty:
        alerts_df["time"] = alerts_df["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
        alerts = alerts_df[
            ["time", "alert_type", "src_ip", "domain", "severity", "details"]
        ].fillna("").head(200).to_dict(orient="records")
    else:
        alerts = []

    event_df = norm_df.copy() if not norm_df.empty else raw_df.copy()

    total_logs = 0 if raw_df.empty else int(len(raw_df))
    alert_count = int(len(alerts_df)) if not alerts_df.empty else 0
    high_alert_count = int(alerts_df["severity"].isin(["high", "critical"]).sum()) if not alerts_df.empty else 0
    low_alert_count = int(alerts_df["severity"].isin(["low"]).sum()) if not alerts_df.empty else 0

    log_activity = {
        "labels": [],
        "total": [],
        "alert": [],
    }

    #Build DNS chart series using raw event volume and detected DNS alert volume
    if not event_df.empty:
        ts_col = None
        for candidate in ["timestamp", "time", "ts"]:
            if candidate in event_df.columns:
                ts_col = candidate
                break

        if ts_col is None:
            event_df["timestamp"] = None
            ts_col = "timestamp"

        event_df["timestamp_dt"] = pd.to_datetime(event_df[ts_col], errors="coerce")
        chart_df = event_df.dropna(subset=["timestamp_dt"]).copy()

        if not chart_df.empty:
            chart_df["bucket"] = chart_df["timestamp_dt"].dt.floor("5min")
            total_counts = chart_df.groupby("bucket").size().sort_index()

            if not alerts_df.empty:
                alerts_chart_df = alerts_df.dropna(subset=["window_start_dt"]).copy()
                if not alerts_chart_df.empty:
                    alerts_chart_df["bucket"] = alerts_chart_df["window_start_dt"].dt.floor("5min")
                    alert_counts = alerts_chart_df.groupby("bucket").size().sort_index()
                else:
                    alert_counts = pd.Series(dtype="int64")
            else:
                alert_counts = pd.Series(dtype="int64")

            if not alert_counts.empty:
                full_idx = total_counts.index.union(alert_counts.index).sort_values()
                full_idx = pd.date_range(full_idx.min(), full_idx.max(), freq="5min")
            else:
                full_idx = pd.date_range(total_counts.index.min(), total_counts.index.max(), freq="5min")

            total_counts = total_counts.reindex(full_idx, fill_value=0)
            alert_counts = alert_counts.reindex(full_idx, fill_value=0)

            log_activity = {
                "labels": [t.strftime("%H:%M") for t in full_idx],
                "total": total_counts.tolist(),
                "alert": alert_counts.tolist(),
            }

    return {
        "summary": {
            "total_logs": total_logs,
            "raw_count": total_logs,
            "alert_count": alert_count,
            "high_alert_count": high_alert_count,
            "low_alert_count": low_alert_count,
        },
        "raw_columns": raw_columns,
        "raw_rows": raw_rows,
        "normalized_columns": normalized_columns,
        "normalized_rows": normalized_rows,
        "alerts": alerts,
        "log_activity": log_activity,
    }


#Builds the main dashboard payload used by the homepage
#Includes KPI counts, alert tables, recent activity, top sources, and chart data
def build_dashboard_payload() -> dict:
    df = safe_read_csv(ALERTS_CSV)
    if df.empty:
        return {
            "exists": False,
            "alerts": [],
            "kpis": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "type_breakdown": {},
            "top_sources": [],
            "recent_activity": [],
            "last_updated": None,
            "traffic_series": {"labels": [], "firewall": [], "auth": [], "ids": [], "dns": []},
            "raw_traffic_series": {"labels": [], "firewall": [], "auth": [], "ids": [], "dns": []},
            "type_counts_raw": {},
        }

    for c in ["event_type", "alert_type", "severity", "details", "window_start", "src_ip"]:
        if c not in df.columns:
            df[c] = None

    df["severity"] = df["severity"].astype(str).str.lower().str.strip()
    df["event_type"] = df["event_type"].astype(str).str.strip()
    df["alert_type"] = df["alert_type"].astype(str).str.strip()
    df["src_ip"] = df["src_ip"].astype(str).replace("nan", "").str.strip()

    df["window_start_dt"] = pd.to_datetime(df["window_start"], errors="coerce")
    df = df.sort_values("window_start_dt", ascending=False)

    #Build dashboard alert traffic series from analysed alert data
    series_df = df.dropna(subset=["window_start_dt"]).copy()
    interval = "5min"
    series_df["bucket"] = series_df["window_start_dt"].dt.floor(interval)

    counts = (
        series_df.groupby(["bucket", "event_type"])
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )

    if not counts.empty:
        full_idx = pd.date_range(counts.index.min(), counts.index.max(), freq=interval)
        counts = counts.reindex(full_idx, fill_value=0)

        #Pad very short timelines so the chart still renders clearly
        if len(counts.index) == 1:
            only = counts.index[0]
            padded_idx = pd.date_range(
                only - pd.Timedelta(minutes=5),
                only + pd.Timedelta(minutes=5),
                freq=interval
            )
            counts = counts.reindex(padded_idx, fill_value=0)

    counts = counts.tail(30)

    traffic_series = {
        "labels": [t.strftime("%H:%M") for t in counts.index],
        "firewall": counts.get("firewall", pd.Series([0] * len(counts), index=counts.index)).tolist(),
        "auth": counts.get("auth", pd.Series([0] * len(counts), index=counts.index)).tolist(),
        "ids": counts.get("ids", pd.Series([0] * len(counts), index=counts.index)).tolist(),
        "dns": counts.get("dns", pd.Series([0] * len(counts), index=counts.index)).tolist(),
    }

    #Build supporting raw traffic and source ranking data
    raw_traffic_series = build_raw_traffic_series(interval="5min", points=30)
    type_counts_raw = series_df["event_type"].value_counts().to_dict()

    sev_counts = df["severity"].value_counts().to_dict()
    kpis = {
        "critical": int(sev_counts.get("critical", 0)),
        "high": int(sev_counts.get("high", 0)),
        "medium": int(sev_counts.get("medium", 0)),
        "low": int(sev_counts.get("low", 0)),
    }

    type_counts = df["event_type"].value_counts().to_dict()
    total = max(1, int(sum(type_counts.values())))
    type_breakdown = {k: round(v * 100 / total, 1) for k, v in type_counts.items()}

    top_sources = build_top_sources_from_raw_logs(limit=20)

    #Build recent activity feed for dashboard card display
    recent = df.head(8).copy()
    recent["time"] = recent["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")

    def shorten(s: str, n: int = 90) -> str:
        s = "" if s is None else str(s)
        s = " ".join(s.split())
        return s if len(s) <= n else (s[: n - 1] + "…")

    recent["details_short"] = recent["details"].apply(lambda x: shorten(x, 95))
    recent_activity = recent[
        ["event_type", "alert_type", "severity", "src_ip", "details_short", "details", "time"]
    ].fillna("").to_dict(orient="records")

    table = df.head(100).copy()
    table["time"] = table["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
    alerts = table[
        ["time", "alert_type", "src_ip", "severity", "details", "event_type", "window_start"]
    ].fillna("").to_dict(orient="records")

    last_updated = datetime.fromtimestamp(ALERTS_CSV.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "exists": True,
        "alerts": alerts,
        "kpis": kpis,
        "type_breakdown": type_breakdown,
        "top_sources": top_sources,
        "recent_activity": recent_activity,
        "last_updated": last_updated,
        "traffic_series": traffic_series,
        "raw_traffic_series": raw_traffic_series,
        "type_counts_raw": type_counts_raw,
    }


#Main dashboard homepage
@app.get("/")
def index():
    return render_template("index.html")


#Returns the full dashboard payload as JSON
@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(build_dashboard_payload())


#Runs the log analysis engine from the dashboard UI
#Returns console output plus refreshed dashboard data
@app.route("/api/run-analysis", methods=["GET", "POST"])
def api_run_analysis():
    try:
        code, output = run_script(SRC_DIR / "main.py")
        payload = build_dashboard_payload()
        return jsonify({
            "ok": code == 0,
            "returncode": code,
            "output": output,
            "dashboard": payload,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


#Runs one of the approved generator scripts from the dashboard UI
@app.route("/api/run-generator", methods=["GET", "POST"])
def api_run_generator():
    data = request.get_json(silent=True) or {}
    script = str(data.get("script", "")).strip()
    if script not in ALLOWED_GENERATORS:
        return jsonify({"ok": False, "error": "Generator not allowed."}), 400

    code, output = run_script(GENERATORS_DIR / script)
    return jsonify({"ok": code == 0, "returncode": code, "output": output})


#Allows CSV log uploads from the UI and saves them to the correct data location
@app.post("/api/upload-log")
def api_upload_log():
    log_type = str(request.form.get("log_type", "")).strip().lower()
    file = request.files.get("file")

    if log_type not in ALLOWED_UPLOADS:
        return jsonify({"ok": False, "error": "Invalid log type."}), 400

    if file is None or file.filename == "":
        return jsonify({"ok": False, "error": "No file uploaded."}), 400

    if not file.filename.lower().endswith(".csv"):
        return jsonify({"ok": False, "error": "Only CSV files are supported."}), 400

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    dest = DATA_DIR / ALLOWED_UPLOADS[log_type]
    file.save(dest)

    return jsonify({
        "ok": True,
        "message": f"Uploaded {file.filename} as {dest.name}",
        "saved_as": dest.name,
        "log_type": log_type,
    })


#Returns list of allowed generator scripts for the UI dropdown/options
@app.get("/api/generators")
def api_generators():
    return jsonify({"generators": sorted(ALLOWED_GENERATORS)})


#Serves generated output files through the browser
@app.get("/outputs/<path:filename>")
def serve_output_file(filename):
    return send_from_directory(OUTPUTS_DIR, filename, as_attachment=False)


#Serves raw data files through the browser
@app.get("/data/<path:filename>")
def serve_data_file(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=False)


#Firewall page and API
@app.get("/firewall")
def firewall_page():
    return render_template("firewall.html")


@app.get("/api/firewall")
def api_firewall():
    return jsonify(build_firewall_payload())


#Authentication page and API
@app.get("/auth")
def auth_page():
    return render_template("auth.html")


@app.get("/api/auth")
def api_auth():
    return jsonify(build_auth_payload())


#IDS page and API
@app.get("/ids")
def ids_page():
    return render_template("ids.html")


@app.get("/api/ids")
def api_ids():
    return jsonify(build_ids_payload())


#DNS page and API
@app.get("/dns")
def dns_page():
    return render_template("dns.html")


@app.get("/api/dns")
def api_dns():
    return jsonify(build_dns_payload())


#Runs the Flask development server locally
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
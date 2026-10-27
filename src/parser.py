from __future__ import annotations  

from dataclasses import dataclass  
from pathlib import Path  
from typing import Dict, Iterable, Optional  

import pandas as pd  


#Container for parsed output (structured log + source name)
@dataclass
class ParseResult:
    df: pd.DataFrame
    source_name: str


#Default schema used to standardise all log formats
DEFAULT_SCHEMA = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "action",
]


def load_csv_log(
    path: str | Path,
    field_map: Dict[str, str],
    source_name: str = "csv",
    schema: Optional[Iterable[str]] = None,
    strict: bool = False,
) -> ParseResult:
    """
    Loads a CSV log file and normalises it into a consistent structure.

    - Maps different log formats into a common schema
    - Handles missing fields
    - Cleans and converts data types
    """

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    #Read raw CSV log
    df_raw = pd.read_csv(path)

    #Use default schema if none provided
    schema = list(schema) if schema is not None else list(DEFAULT_SCHEMA)

    #Create normalised dataframe
    norm = pd.DataFrame()

    #Map CSV columns to common schema fields
    for common_field, csv_col in field_map.items():
        if csv_col in df_raw.columns:
            norm[common_field] = df_raw[csv_col]
        else:
            #Handle missing fields depending on strict mode
            if strict:
                raise ValueError(
                    f"Missing expected column '{csv_col}' for field '{common_field}' in {path.name}. "
                    f"Available columns: {list(df_raw.columns)}"
                )
            norm[common_field] = pd.NA

    #Ensure all required schema fields exist
    for col in schema:
        if col not in norm.columns:
            norm[col] = pd.NA

    #Convert timestamp to datetime format
    if "timestamp" in norm.columns:
        norm["timestamp"] = pd.to_datetime(norm["timestamp"], errors="coerce", utc=False)

    #Basic cleaning of string fields
    for col in ["src_ip", "dst_ip", "action"]:
        if col in norm.columns:
            norm[col] = norm[col].astype("string").str.strip()

    #Convert port values to numeric
    if "dst_port" in norm.columns:
        norm["dst_port"] = pd.to_numeric(norm["dst_port"], errors="coerce")

    #Add metadata for tracking log origin
    norm["event_type"] = source_name
    norm["source_file"] = path.name

    #Store original raw log line for debugging/reporting
    norm["raw"] = df_raw.astype(str).agg(" | ".join, axis=1)

    #Return structured result
    return ParseResult(df=norm, source_name=source_name)
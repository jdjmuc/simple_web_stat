"""
Parser for Apache Combined Log Format files.
Converts log entries into Polars DataFrames backed by Pydantic models.
"""

import hashlib
import re
from datetime import datetime, date
from pathlib import Path
from typing import List, Union

import polars as pl
from simple_web_stat.model import ApacheLogEntry


# Regex pattern for Apache Combined Log Format
# Format: remote_host ident authuser [timestamp] "request" status_code bytes_sent "referrer" "user_agent"
# Supports both IPv4 and IPv6 addresses
# Handles quoted fields that may contain escaped quotes
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<remote_host>[\da-fA-F.:]+|\S+)\s+'  # IPv4, IPv6, or hostname
    r'(?P<ident>\S+)\s+'
    r'(?P<authuser>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request_line>(?:\\.|[^"])*)"\s+'  # Request line with escaped char support
    r'(?P<status_code>\d+)\s+'
    r'(?P<bytes_sent>\d+|-)\s+'
    r'"(?P<referrer>(?:\\.|[^"])*)"\s+'  # Referrer with escaped char support
    r'"(?P<user_agent>(?:\\.|[^"])*)"\s*$'  # User-agent with escaped char support
)

# Regex pattern for parsing the request line (e.g., "GET /path HTTP/1.1")
REQUEST_LINE_PATTERN = re.compile(
    r'^(?P<http_method>\S+)\s+(?P<uri>\S+)\s+(?P<http_version>\S+)$'
)


def obfuscate_ip(ip: str, date_value: date) -> str:
    """
    Obfuscate an IP address by hashing it with the date as part of the seed.
    
    Same IP on the same day gets the same hash (enables daily statistics),
    but different days produce different hashes (prevents long-term IP tracking).
    
    Args:
        ip: IP address to obfuscate
        date_value: Date to use as part of the hash seed
        
    Returns:
        Hashed and shortened IP address (16 hex characters)
    """
    input = f"{date_value}:{ip}"
    hashed = hashlib.sha256(input.encode()).hexdigest()
    return hashed[:16]  # Use first 16 characters for readability


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse Apache log timestamp format.
    
    Example: "19/Dec/2025:00:08:24 +0100"
    """
    return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")


def parse_log_line(line: str) -> Union[ApacheLogEntry, None]:
    """
    Parse a single Apache log line into an ApacheLogEntry.
    
    Returns None if the line cannot be parsed.
    Handles malformed lines by cleaning them up first.
    """
    # Strip leading/trailing whitespace and handle lines with embedded newlines
    line = line.rstrip('\n\r')
    
    # Skip lines that appear incomplete (contain embedded newlines from truncation)
    if '\n' in line or '\r' in line:
        return None
    
    match = APACHE_LOG_PATTERN.match(line)
    if not match:
        return None
    
    groups = match.groupdict()
    
    # Handle "-" as empty request (common for 4xx errors)
    if groups["request_line"] == "-":
        http_method = "-"
        uri = "-"
        http_version = "-"
    else:
        # Parse request line
        request_match = REQUEST_LINE_PATTERN.match(groups["request_line"])
        if not request_match:
            return None
        
        request_groups = request_match.groupdict()
        http_method = request_groups["http_method"]
        uri = request_groups["uri"]
        http_version = request_groups["http_version"]
    
    # Convert bytes_sent to int (handle "-" as 0)
    bytes_sent = int(groups["bytes_sent"]) if groups["bytes_sent"] != "-" else 0
    
    # Handle "-" values as None for optional fields
    ident = None if groups["ident"] == "-" else groups["ident"]
    authuser = None if groups["authuser"] == "-" else groups["authuser"]
    referrer = None if groups["referrer"] == "-" else groups["referrer"]
    user_agent = None if groups["user_agent"] == "-" else groups["user_agent"]
    
    try:
        entry = ApacheLogEntry(
            remote_host=groups["remote_host"],
            ident=ident,
            authuser=authuser,
            timestamp=parse_timestamp(groups["timestamp"]),
            http_method=http_method,
            uri=uri,
            http_version=http_version,
            status_code=int(groups["status_code"]),
            bytes_sent=bytes_sent,
            referrer=referrer,
            user_agent=user_agent,
        )
        return entry
    except (ValueError, TypeError) as e:
        print(f"Error parsing log line: {line}\n  Error: {e}")
        return None


def parse_log_file(filepath: Union[str, Path]) -> pl.DataFrame:
    """
    Parse an Apache Combined Log Format file into a Polars DataFrame.
    
    Args:
        filepath: Path to the Apache log file
        
    Returns:
        A Polars DataFrame with columns matching ApacheLogEntry fields
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")
    
    entries: List[ApacheLogEntry] = []
    
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:  # Skip empty lines
                continue
            
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
            else:
                print(f"Warning: Could not parse line {line_num}: {line[:100]}")
    
    if not entries:
        raise ValueError("No valid log entries found in the file")
    
    # Convert Pydantic models to dictionaries for Polars
    data = [entry.model_dump() for entry in entries]
    
    # Create DataFrame
    df = pl.DataFrame(data)
    
    # Obfuscate IP addresses based on the date from each entry
    df = df.with_columns([
        pl.struct(["remote_host", "timestamp"])
        .map_elements(
            lambda row: obfuscate_ip(row["remote_host"], row["timestamp"].date()),
            return_dtype=pl.Utf8
        )
        .alias("remote_host")
    ])
    
    return df


def parse_log_files(directory: Union[str, Path], pattern: str = "*.log") -> pl.DataFrame:
    """
    Parse multiple Apache log files from a directory into a single Polars DataFrame.
    Skips empty files gracefully.
    
    Args:
        directory: Path to directory containing log files
        pattern: Glob pattern for matching log files (default: "*.log")
        
    Returns:
        A combined Polars DataFrame with all log entries
    """
    directory = Path(directory)
    
    if not directory.is_dir():
        raise NotADirectoryError(f"Directory not found: {directory}")
    
    log_files = list(directory.glob(pattern))
    
    if not log_files:
        raise ValueError(f"No log files matching pattern '{pattern}' found in {directory}")
    
    combined_df = None
    for log_file in sorted(log_files):
        # Skip empty files
        if log_file.stat().st_size == 0:
            print(f"Skipping {log_file.name} (empty file)")
            continue
            
        print(f"Parsing {log_file.name}...")
        try:
            df = parse_log_file(log_file)
            
            # Concatenate incrementally to avoid storing all dataframes in memory
            if combined_df is None:
                combined_df = df
            else:
                combined_df = pl.concat([combined_df, df])
        except ValueError as e:
            print(f"Skipping {log_file.name}: {e}")
            continue
    
    if combined_df is None:
        raise ValueError("No valid log entries found in any file")
        
    return combined_df

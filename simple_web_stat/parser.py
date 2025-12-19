"""
Parser for Apache Combined Log Format files.
Converts log entries into Polars DataFrames backed by Pydantic models.
"""

import hashlib
import re
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, date
from pathlib import Path
from typing import List, Optional, Union
import os

import polars as pl
from simple_web_stat.model import ApacheLogEntry


# Regex pattern for Apache Combined Log Format
# Format: remote_host ident authuser [timestamp] "request" status_code bytes_sent "referrer" "user_agent"
# Supports both IPv4 and IPv6 addresses
# Handles quoted fields that may contain escaped quotes
# More lenient with malformed entries
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<remote_host>[\da-fA-F.:]+|\S+)\s+'  # IPv4, IPv6, or hostname
    r'(?P<ident>\S+)\s+'
    r'(?P<authuser>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request_line>(?:\\.|[^"])*)"\s+'  # Request line with escaped char support
    r'(?P<status_code>\d+)\s+'
    r'(?P<bytes_sent>\d+|-)(?:\s+|$)'  # bytes_sent, may be at end of line
    r'(?:\s*"(?P<referrer>(?:\\.|[^"])*?)")?'  # Optional referrer
    r'(?:\s*"(?P<user_agent>(?:\\.|[^"])*?)")?'  # Optional user-agent
    r'.*$'  # Allow trailing content
)

# Regex pattern for parsing the request line (e.g., "GET /path HTTP/1.1")
# More lenient: allows missing parts
REQUEST_LINE_PATTERN = re.compile(
    r'^(?P<http_method>\S+)\s+(?P<uri>\S*)\s*(?P<http_version>\S*)$'
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
    Very lenient - accepts entries with missing or malformed trailing fields.
    """
    # Strip leading/trailing whitespace and handle lines with embedded newlines
    line = line.rstrip('\n\r')
    
    # Skip lines that appear incomplete (contain embedded newlines from truncation)
    if '\n' in line or '\r' in line:
        return None
    
    # Skip lines with only whitespace or quotes
    if not line or line.strip() in ('', '""', '"-"'):
        return None
    
    match = APACHE_LOG_PATTERN.match(line)
    if not match:
        return None
    
    groups = match.groupdict()
    
    # Get the request line and validate/parse it
    request_line = groups["request_line"].strip()
    
    # Skip empty or malformed request lines (just newlines, binary data, etc)
    if not request_line or '\\n' in request_line or '\\x' in request_line:
        return None
    
    # Handle "-" as empty request (common for 4xx errors)
    if request_line == "-":
        http_method = "-"
        uri = "-"
        http_version = "-"
    else:
        # Parse request line - be lenient with missing parts
        request_match = REQUEST_LINE_PATTERN.match(request_line)
        if not request_match:
            # If request line doesn't match standard format, skip it
            return None
        
        request_groups = request_match.groupdict()
        http_method = request_groups["http_method"]
        uri = request_groups.get("uri") or "-"
        http_version = request_groups.get("http_version") or "-"
        
        # Skip if we couldn't parse at least the method
        if not http_method:
            return None
        
        # For truly malformed methods that don't look like HTTP, skip
        if http_method not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]:
            # Could be corrupted data, but give it a chance if the rest looks OK
            pass
    
    # Convert bytes_sent to int (handle "-" as 0)
    try:
        bytes_sent = int(groups["bytes_sent"]) if groups["bytes_sent"] != "-" else 0
    except (ValueError, TypeError):
        bytes_sent = 0
    
    # Handle "-" values as None for optional fields
    ident = None if groups["ident"] == "-" else groups["ident"]
    authuser = None if groups["authuser"] == "-" else groups["authuser"]
    
    # Handle referrer/user_agent which may be None from regex
    referrer = groups.get("referrer")
    referrer = None if not referrer or referrer == "-" else referrer
    
    user_agent = groups.get("user_agent")
    user_agent = None if not user_agent or user_agent == "-" else user_agent
    
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
    except (ValueError, TypeError):
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


def parse_log_files(directory: Union[str, Path], pattern: str = "*.log", num_workers: Optional[int] = None) -> pl.DataFrame:
    """
    Parse multiple Apache log files from a directory into a single Polars DataFrame.
    Skips empty files gracefully and uses parallel processing for speed.
    
    Args:
        directory: Path to directory containing log files
        pattern: Glob pattern for matching log files (default: "*.log")
        num_workers: Number of parallel workers (default: CPU count)
        
    Returns:
        A combined Polars DataFrame with all log entries
    """
    directory = Path(directory)
    
    if not directory.is_dir():
        raise NotADirectoryError(f"Directory not found: {directory}")
    
    log_files = list(directory.glob(pattern))
    
    if not log_files:
        raise ValueError(f"No log files matching pattern '{pattern}' found in {directory}")
    
    # Filter out empty files
    non_empty_files = [f for f in sorted(log_files) if f.stat().st_size > 0]
    
    if not non_empty_files:
        raise ValueError(f"All log files in {directory} are empty")
    
    print(f"Parsing {len(non_empty_files)} files with parallel processing...")
    
    # Set number of workers to CPU count if not specified
    if num_workers is None:
        num_workers = os.cpu_count() or 4
    
    dataframes = []
    failed_files = []
    
    # Use ProcessPoolExecutor for parallel file parsing
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(parse_log_file, f): f for f in non_empty_files}
        
        for future in futures:
            log_file = futures[future]
            try:
                df = future.result()
                dataframes.append(df)
                print(f"✓ Parsed {log_file.name}: {len(df)} entries")
            except ValueError as e:
                print(f"⊘ Skipped {log_file.name}: {e}")
                failed_files.append(log_file.name)
            except Exception as e:
                print(f"✗ Error parsing {log_file.name}: {e}")
                failed_files.append(log_file.name)
    
    if not dataframes:
        raise ValueError("No valid log entries found in any file")
    
    print(f"Combining {len(dataframes)} dataframes...")
    combined_df = pl.concat(dataframes)
    
    if failed_files:
        print(f"Warning: {len(failed_files)} files were skipped")
    
    return combined_df

"""
monitor.py — Log Tailer
Continuously reads new lines from the Nginx JSON access log
and parses them into structured dicts for the rest of the pipeline.
"""

import json
import time
import os
from datetime import datetime


def parse_log_line(line: str) -> dict | None:
    """
    Parse a single JSON log line from Nginx.
    Returns a dict with normalized fields, or None if the line is invalid.
    """
    line = line.strip()
    if not line:
        return None

    try:
        entry = json.loads(line)

        return {
            "source_ip":     entry.get("source_ip", "").split(",")[0].strip(),
            "timestamp":     entry.get("timestamp", datetime.utcnow().isoformat()),
            "method":        entry.get("method", ""),
            "path":          entry.get("path", ""),
            "status":        int(entry.get("status", 0)),
            "response_size": int(entry.get("response_size", 0)),
            "request_time":  float(entry.get("request_time", 0.0)),
            "user_agent":    entry.get("user_agent", ""),
            "parsed_at":     time.time(),
        }

    except (json.JSONDecodeError, ValueError):
        return None


def tail_log(log_path: str, callback):
    """
    Continuously tail the Nginx log file line by line.
    Runs forever — meant to be in its own thread.
    """
    print(f"[monitor] Waiting for log file: {log_path}")

    while not os.path.exists(log_path):
        time.sleep(1)

    print(f"[monitor] Log file found. Starting tail...")

    with open(log_path, "r") as f:
        # Seek to end on startup — ignore historical lines
        f.seek(0, 2)
        print(f"[monitor] Seeked to end, position={f.tell()}")  # DEBUG
        last_size = f.tell()

        while True:
            line = f.readline()

            if line:
                entry = parse_log_line(line)
                if entry and entry["source_ip"]:
                    print(f"[monitor] Entry: {entry['source_ip']} {entry['method']} {entry['path']} {entry['status']}")  # DEBUG
                    callback(entry)
                else:
                    print(f"[monitor] Skipped line: {repr(line[:80])}")  # DEBUG
            else:
                # No new line yet — check for log rotation
                try:
                    current_size = os.path.getsize(log_path)
                    if current_size < last_size:
                        print("[monitor] Log rotation detected. Reopening.")
                        f.seek(0)
                    last_size = current_size
                except FileNotFoundError:
                    print("[monitor] Log file missing. Waiting...")
                    time.sleep(2)
                    while not os.path.exists(log_path):
                        time.sleep(1)
                    f = open(log_path, "r")
                    f.seek(0, 2)

                time.sleep(0.1)

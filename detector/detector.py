"""
detector.py — Anomaly Detection Engine

Uses two deque-based sliding windows (last 60 seconds):
  - One per IP address
  - One global (all traffic)

Every second, computes current rate and compares against baseline.
Fires anomaly if EITHER condition is true:
  - z-score > 3.0  (statistical deviation)
  - rate > 5x baseline mean  (absolute multiplier)

Also detects error surges per IP (4xx/5xx rate 3x baseline error rate).
"""

import time
import threading
import math
from collections import deque, defaultdict
from config import cfg


class AnomalyDetector:
    def __init__(self, baseline, on_ip_anomaly, on_global_anomaly):
        """
        Args:
            baseline:          BaselineCalculator instance
            on_ip_anomaly:     callback(ip, rate, mean, stddev, reason)
            on_global_anomaly: callback(rate, mean, stddev, reason)
        """
        self.baseline = baseline

        # Callbacks fired when anomaly is detected
        self.on_ip_anomaly     = on_ip_anomaly
        self.on_global_anomaly = on_global_anomaly

        # Sliding window config
        self.window_seconds = cfg["sliding_window_seconds"]  # 60

        # Anomaly thresholds (from config — never hardcoded)
        self.zscore_threshold     = cfg["zscore_threshold"]           # 3.0
        self.rate_multiplier      = cfg["rate_multiplier_threshold"]  # 5.0
        self.error_surge_mult     = cfg["error_surge_multiplier"]     # 3.0

        # --- Sliding Windows ---
        # Global window: deque of timestamps (one per request)
        # We count how many timestamps fall within the last 60s
        self.global_window: deque = deque()

        # Per-IP windows: { ip: deque of timestamps }
        self.ip_windows: defaultdict = defaultdict(deque)

        # Per-IP error windows: { ip: deque of timestamps } (4xx/5xx only)
        self.ip_error_windows: defaultdict = defaultdict(deque)

        # IPs currently banned — skip detection for them
        self.banned_ips: set = set()

        # Track which IPs have tightened thresholds due to error surge
        self.tightened_ips: set = set()

        self._lock = threading.Lock()

    def record_request(self, entry: dict):
        """
        Called for every parsed log entry.
        Adds the request timestamp to the appropriate sliding windows.

        Eviction logic:
          - We store the raw timestamp (time.time()) of each request
          - On every read, we pop from the LEFT of the deque
            while the oldest entry is outside the 60s window
          - This keeps the deque always representing the last 60 seconds
        """
        now = entry["parsed_at"]
        ip  = entry["source_ip"]

        with self._lock:
            # Add to global window
            self.global_window.append(now)

            # Add to per-IP window
            self.ip_windows[ip].append(now)

            # Track errors per IP
            if entry["status"] >= 400:
                self.ip_error_windows[ip].append(now)

    def _evict_old(self, window: deque, cutoff: float):
        """
        Remove entries from the LEFT of the deque that are older than cutoff.
        Since we always append to the right in time order,
        the left side is always the oldest — O(k) eviction where k = expired entries.
        """
        while window and window[0] < cutoff:
            window.popleft()

    def _current_rate(self, window: deque, now: float) -> float:
        """
        Evict stale entries then return the count of requests
        in the last window_seconds as a per-second rate.
        """
        cutoff = now - self.window_seconds
        self._evict_old(window, cutoff)
        # Rate = total requests in window / window size in seconds
        return len(window) / self.window_seconds

    def _compute_zscore(self, rate: float, mean: float, stddev: float) -> float:
        """
        Z-score = how many standard deviations above the mean we are.
        Guards against stddev=0 with the floor set in baseline.py.
        """
        return (rate - mean) / stddev

    def _check_anomaly(self, rate: float, mean: float, stddev: float,
                        zscore_threshold: float, multiplier: float) -> tuple[bool, str]:
        """
        Returns (is_anomalous, reason_string).
        Fires if EITHER condition is true — whichever fires first.
        """
        zscore = self._compute_zscore(rate, mean, stddev)

        if zscore > zscore_threshold:
            return True, f"zscore={zscore:.2f} > threshold={zscore_threshold}"

        if mean > 0 and rate > (multiplier * mean):
            return True, f"rate={rate:.2f} > {multiplier}x mean={mean:.2f}"

        return False, ""

    def run_detection_loop(self):
        """
        Runs forever in its own thread.
        Every second:
          1. Compute global rate → check for global anomaly
          2. For each active IP → check for per-IP anomaly
          3. For each active IP → check for error surge
        """
        while True:
            time.sleep(1)
            now = time.time()

            mean, stddev = self.baseline.get_baseline()
            error_mean, error_stddev = self.baseline.get_error_baseline()

            with self._lock:
                # --- Global anomaly check ---
                global_rate = self._current_rate(self.global_window, now)
                is_anomalous, reason = self._check_anomaly(
                    global_rate, mean, stddev,
                    self.zscore_threshold, self.rate_multiplier
                )
                if is_anomalous:
                    # Release lock before calling callback (avoids deadlock)
                    self._lock.release()
                    try:
                        self.on_global_anomaly(global_rate, mean, stddev, reason)
                    finally:
                        self._lock.acquire()

                # --- Per-IP anomaly + error surge check ---
                # Snapshot IPs to avoid mutation during iteration
                active_ips = list(self.ip_windows.keys())

            for ip in active_ips:
                if ip in self.banned_ips:
                    continue  # already banned — skip

                with self._lock:
                    ip_window    = self.ip_windows[ip]
                    err_window   = self.ip_error_windows.get(ip, deque())
                    ip_rate      = self._current_rate(ip_window, now)
                    ip_err_rate  = self._current_rate(err_window, now) if err_window else 0.0

                # Check if this IP has an error surge
                # If so, tighten its detection thresholds
                err_surge = (
                    error_mean > 0 and
                    ip_err_rate > (self.error_surge_mult * error_mean)
                )

                if err_surge and ip not in self.tightened_ips:
                    print(f"[detector] Error surge for {ip} — tightening thresholds")
                    self.tightened_ips.add(ip)

                # Use tighter thresholds if IP is in error surge
                z_thresh   = self.zscore_threshold * 0.6 if ip in self.tightened_ips else self.zscore_threshold
                mult       = self.rate_multiplier  * 0.6 if ip in self.tightened_ips else self.rate_multiplier

                is_anomalous, reason = self._check_anomaly(
                    ip_rate, mean, stddev, z_thresh, mult
                )

                if is_anomalous:
                    suffix = " [error-surge-tightened]" if ip in self.tightened_ips else ""
                    self.on_ip_anomaly(ip, ip_rate, mean, stddev, reason + suffix)

    def ban_ip(self, ip: str):
        """Called by blocker after banning — stops detection firing repeatedly."""
        with self._lock:
            self.banned_ips.add(ip)

    def unban_ip(self, ip: str):
        """Called by unbanner after releasing a ban."""
        with self._lock:
            self.banned_ips.discard(ip)
            self.tightened_ips.discard(ip)

    def get_top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """
        Returns top N IPs by request count in the current window.
        Used by the dashboard.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            counts = []
            for ip, window in self.ip_windows.items():
                self._evict_old(window, cutoff)
                counts.append((ip, len(window)))

        counts.sort(key=lambda x: x[1], reverse=True)
        return counts[:n]

    def get_global_rate(self) -> float:
        """Current global requests/sec — used by dashboard."""
        now = time.time()
        with self._lock:
            return self._current_rate(self.global_window, now)

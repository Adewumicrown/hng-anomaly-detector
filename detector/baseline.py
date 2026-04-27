"""
baseline.py — Rolling Baseline Calculator

Maintains a 30-minute rolling window of per-second request counts.
Recalculates mean and stddev every 60 seconds.
Stores counts in per-hour slots and prefers current hour's data
when it has enough samples.
"""

import time
import math
import threading
from collections import deque
from config import cfg


class BaselineCalculator:
    def __init__(self):
        # How many seconds of history to keep (30 min = 1800 seconds)
        self.window_seconds = cfg["baseline_window_minutes"] * 60

        # Recalculate every N seconds
        self.recalc_interval = cfg["baseline_recalc_interval_seconds"]

        # Minimum samples before we trust the baseline
        self.min_samples = cfg["baseline_min_samples"]

        # Rolling window of (timestamp, count) tuples — one entry per second
        # deque automatically discards old entries when maxlen is hit
        self.window: deque = deque()

        # Per-hour slots: { hour_int: [counts] }
        # hour_int = int(time.time() // 3600)
        self.hourly_slots: dict = {}

        # Current effective baseline values
        self.effective_mean: float = 1.0    # floor of 1.0 — never zero
        self.effective_stddev: float = 1.0  # floor of 1.0

        # Error rate baseline (4xx/5xx per second)
        self.error_mean: float = 0.1
        self.error_stddev: float = 0.1

        # Per-second counters (reset every second by main loop)
        self._current_second: int = int(time.time())
        self._count_this_second: int = 0
        self._errors_this_second: int = 0

        # Error rate rolling window
        self.error_window: deque = deque()

        self._lock = threading.Lock()

    def record_request(self, status: int):
        """
        Called for every incoming request.
        Increments the current-second counter.
        """
        now_second = int(time.time())

        with self._lock:
            if now_second != self._current_second:
                # Second has ticked over — save last second's count to window
                self._flush_second(self._current_second,
                                   self._count_this_second,
                                   self._errors_this_second)
                self._current_second = now_second
                self._count_this_second = 0
                self._errors_this_second = 0

            self._count_this_second += 1
            if status >= 400:
                self._errors_this_second += 1

    def _flush_second(self, second: int, count: int, errors: int):
        """
        Save a completed second's count into the rolling window
        and the appropriate hourly slot.
        Internal — always called under lock.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Add to rolling window
        self.window.append((second, count))
        self.error_window.append((second, errors))

        # Evict entries older than 30 minutes from the left
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()
        while self.error_window and self.error_window[0][0] < cutoff:
            self.error_window.popleft()

        # Add to hourly slot
        hour_key = second // 3600
        if hour_key not in self.hourly_slots:
            self.hourly_slots[hour_key] = []
        self.hourly_slots[hour_key].append(count)

        # Keep only last 3 hours of slots to save memory
        cutoff_hour = (now // 3600) - 2
        self.hourly_slots = {
            h: v for h, v in self.hourly_slots.items() if h >= cutoff_hour
        }

    def recalculate(self) -> dict:
        """
        Recalculate mean and stddev from the rolling window.
        Prefers current hour's slot if it has enough data (>= min_samples).
        Falls back to full 30-min window otherwise.

        Returns a dict with the new baseline values for audit logging.
        """
        with self._lock:
            current_hour = int(time.time()) // 3600
            current_slot = self.hourly_slots.get(current_hour, [])

            # Prefer current hour if it has enough samples
            if len(current_slot) >= self.min_samples:
                counts = current_slot
                source = "current_hour"
            elif self.window:
                counts = [c for _, c in self.window]
                source = "rolling_window"
            else:
                # Not enough data yet — keep floor values
                return {
                    "effective_mean":   self.effective_mean,
                    "effective_stddev": self.effective_stddev,
                    "source":           "floor",
                    "sample_count":     0,
                }

            mean = sum(counts) / len(counts)
            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
            stddev = math.sqrt(variance)

            # Apply floors — never allow mean or stddev to be zero
            # This prevents division by zero in z-score calculation
            self.effective_mean   = max(mean, 1.0)
            self.effective_stddev = max(stddev, 1.0)

            # Recalculate error baseline too
            if self.error_window:
                error_counts = [c for _, c in self.error_window]
                e_mean = sum(error_counts) / len(error_counts)
                e_var  = sum((x - e_mean) ** 2 for x in error_counts) / len(error_counts)
                self.error_mean   = max(e_mean, 0.1)
                self.error_stddev = max(math.sqrt(e_var), 0.1)

            return {
                "effective_mean":   self.effective_mean,
                "effective_stddev": self.effective_stddev,
                "error_mean":       self.error_mean,
                "error_stddev":     self.error_stddev,
                "source":           source,
                "sample_count":     len(counts),
            }

    def get_baseline(self) -> tuple[float, float]:
        """Quick read of current mean and stddev — used by detector."""
        return self.effective_mean, self.effective_stddev

    def get_error_baseline(self) -> tuple[float, float]:
        """Quick read of error rate baseline."""
        return self.error_mean, self.error_stddev

    def run_recalc_loop(self, audit_callback=None):
        """
        Runs forever in its own thread.
        Recalculates baseline every recalc_interval seconds
        and optionally calls audit_callback with the result.
        """
        while True:
            time.sleep(self.recalc_interval)
            result = self.recalculate()
            print(f"[baseline] Recalculated — mean={result['effective_mean']:.2f} "
                  f"stddev={result['effective_stddev']:.2f} "
                  f"source={result['source']} "
                  f"samples={result['sample_count']}")
            if audit_callback:
                audit_callback("BASELINE_RECALC", result)

"""
unbanner.py — Auto-Unban with Backoff Schedule

Checks the ban registry every 30 seconds.
Releases bans according to the backoff schedule:
  Ban 1 → release after 10 min
  Ban 2 → release after 30 min
  Ban 3 → release after 2 hours
  Ban 4+ → permanent (never released)

Notifies detector to resume watching the IP after unban.
"""

import time
import threading
from config import cfg


class Unbanner:
    def __init__(self, blocker, detector, audit_callback=None):
        """
        Args:
            blocker:        Blocker instance (has ban_registry + unban())
            detector:       AnomalyDetector instance (to re-enable detection)
            audit_callback: fn(action, data) for audit log
        """
        self.blocker        = blocker
        self.detector       = detector
        self.audit_callback = audit_callback

        # Backoff schedule in seconds from config
        # e.g. [600, 1800, 7200, "permanent"]
        self.schedule = cfg.get("unban_schedule", [600, 1800, 7200, "permanent"])

        # Check interval — every 30 seconds
        self.check_interval = 30

    def _get_ban_duration(self, ban_count: int):
        """
        Returns the ban duration in seconds for this ban count.
        Returns None if the ban is permanent.
        """
        index = min(ban_count - 1, len(self.schedule) - 1)
        val   = self.schedule[index]
        if val == "permanent":
            return None
        return int(val)

    def run_unban_loop(self):
        """
        Runs forever in its own thread.
        Every 30 seconds, checks all banned IPs and releases
        those whose ban duration has expired.
        """
        print("[unbanner] Auto-unban loop started")

        while True:
            time.sleep(self.check_interval)
            now = time.time()

            # Snapshot current bans to avoid holding lock during unban
            registry = self.blocker.get_ban_registry()

            for ip, entry in registry.items():
                ban_count  = entry.get("ban_count", 1)
                banned_at  = entry.get("banned_at", now)
                duration   = self._get_ban_duration(ban_count)

                if duration is None:
                    # Permanent ban — never release
                    print(f"[unbanner] {ip} is permanently banned — skipping")
                    continue

                elapsed = now - banned_at

                if elapsed >= duration:
                    print(f"[unbanner] Releasing ban for {ip} "
                          f"(ban #{ban_count}, elapsed={elapsed:.0f}s, "
                          f"duration={duration}s)")

                    # Remove iptables rule + fire Slack alert
                    self.blocker.unban(ip)

                    # Re-enable anomaly detection for this IP
                    self.detector.unban_ip(ip)

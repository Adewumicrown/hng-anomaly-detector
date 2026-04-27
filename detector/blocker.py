"""
blocker.py — IP Banning via iptables

On per-IP anomaly, adds an iptables DROP rule within 10 seconds.
Tracks ban state and ban count per IP for the unbanner's backoff schedule.
On non-Linux systems (local dev), logs the ban instead of running iptables.
"""

import subprocess
import threading
import time
import platform
from datetime import datetime
from config import cfg


class Blocker:
    def __init__(self, audit_callback=None, notify_callback=None):
        """
        Args:
            audit_callback:  fn(action, data) — writes to audit log
            notify_callback: fn(event, data)  — sends Slack alert
        """
        self.audit_callback  = audit_callback
        self.notify_callback = notify_callback

        # Ban registry: { ip: { "banned_at": float, "ban_count": int, "reason": str } }
        self.ban_registry: dict = {}

        # Detect if we're on Linux — iptables only works there
        self.is_linux = platform.system() == "Linux"
        if not self.is_linux:
            print("[blocker] Non-Linux system detected — iptables calls will be simulated")

        self._lock = threading.Lock()

    def _run_iptables(self, action: str, ip: str) -> bool:
        """
        Run an iptables command.
        action: "-A" to add rule, "-D" to delete rule.
        Returns True on success, False on failure.
        """
        if not self.is_linux:
            # Local dev simulation — just log it
            print(f"[blocker] [SIMULATED] iptables {action} INPUT -s {ip} -j DROP")
            return True

        cmd = ["iptables", action, "INPUT", "-s", ip, "-j", "DROP"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5  # never block longer than 5s
            )
            if result.returncode != 0:
                print(f"[blocker] iptables error: {result.stderr.strip()}")
                return False
            return True

        except subprocess.TimeoutExpired:
            print(f"[blocker] iptables command timed out for {ip}")
            return False
        except FileNotFoundError:
            print(f"[blocker] iptables not found — are you root?")
            return False

    def ban(self, ip: str, reason: str, rate: float,
            mean: float, stddev: float) -> bool:
        """
        Ban an IP by adding an iptables DROP rule.
        Updates ban registry with ban time and ban count.
        Fires audit log and Slack alert.

        Returns True if ban was applied, False if IP was already banned.
        """
        with self._lock:
            if ip in self.ban_registry:
                # Already banned — don't double-ban
                return False

            banned_at = time.time()
            ban_count = self.ban_registry.get(ip, {}).get("ban_count", 0) + 1

            # Apply the iptables rule
            success = self._run_iptables("-A", ip)

            if not success:
                print(f"[blocker] Failed to ban {ip}")
                return False

            # Record in registry
            self.ban_registry[ip] = {
                "banned_at":  banned_at,
                "ban_count":  ban_count,
                "reason":     reason,
                "rate":       rate,
                "mean":       mean,
                "stddev":     stddev,
            }

        # Determine ban duration label for alerts
        duration = self._get_ban_duration_label(ban_count)

        print(f"[blocker] BANNED {ip} | reason={reason} | "
              f"rate={rate:.2f} | mean={mean:.2f} | duration={duration}")

        # Audit log
        if self.audit_callback:
            self.audit_callback("BAN", {
                "ip":        ip,
                "condition": reason,
                "rate":      rate,
                "baseline":  mean,
                "duration":  duration,
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Slack alert
        if self.notify_callback:
            self.notify_callback("BAN", {
                "ip":        ip,
                "condition": reason,
                "rate":      rate,
                "baseline":  mean,
                "stddev":    stddev,
                "duration":  duration,
                "timestamp": datetime.utcnow().isoformat(),
            })

        return True

    def unban(self, ip: str) -> bool:
        """
        Remove an iptables DROP rule for the given IP.
        Called by unbanner.py on the backoff schedule.
        Returns True if rule was removed, False if IP wasn't banned.
        """
        with self._lock:
            if ip not in self.ban_registry:
                return False

            entry    = self.ban_registry.pop(ip)
            ban_count = entry["ban_count"]

        success = self._run_iptables("-D", ip)

        duration = self._get_ban_duration_label(ban_count)

        print(f"[blocker] UNBANNED {ip} | ban_count={ban_count}")

        # Audit log
        if self.audit_callback:
            self.audit_callback("UNBAN", {
                "ip":        ip,
                "condition": entry.get("reason", ""),
                "rate":      entry.get("rate", 0),
                "baseline":  entry.get("mean", 0),
                "duration":  duration,
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Slack alert
        if self.notify_callback:
            self.notify_callback("UNBAN", {
                "ip":        ip,
                "ban_count": ban_count,
                "duration":  duration,
                "timestamp": datetime.utcnow().isoformat(),
            })

        return success

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self.ban_registry

    def get_ban_registry(self) -> dict:
        """Snapshot of current bans — used by dashboard."""
        with self._lock:
            return dict(self.ban_registry)

    def get_ban_count(self, ip: str) -> int:
        """How many times this IP has been banned — used by unbanner."""
        with self._lock:
            return self.ban_registry.get(ip, {}).get("ban_count", 0)

    def _get_ban_duration_label(self, ban_count: int) -> str:
        """
        Map ban count to duration label matching the backoff schedule.
        ban_count 1 → 10 min, 2 → 30 min, 3 → 2 hours, 4+ → permanent
        """
        schedule = cfg.get("unban_schedule", [600, 1800, 7200, "permanent"])
        index    = min(ban_count - 1, len(schedule) - 1)
        val      = schedule[index]
        if val == "permanent":
            return "permanent"
        minutes = val // 60
        if minutes >= 60:
            return f"{minutes // 60}h"
        return f"{minutes}min"

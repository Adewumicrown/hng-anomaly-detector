"""
main.py — Daemon Entry Point

Wires all modules together and starts them as threads:
  1. Notifier     — Slack alert queue worker
  2. Monitor      — Nginx log tailer
  3. Baseline     — Rolling 30-min recalculator
  4. Detector     — Sliding window anomaly engine
  5. Unbanner     — Auto-unban backoff loop
  6. Dashboard    — Flask metrics UI on port 8080

All threads are daemon threads except the dashboard which
runs on the main thread to keep the process alive.
"""

import threading
import time
import os
from datetime import datetime

from config   import cfg
from monitor  import tail_log
from baseline import BaselineCalculator
from detector import AnomalyDetector
from blocker  import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard


# ── Audit Logger ─────────────────────────────────────────────────────────────

AUDIT_LOG_PATH = cfg.get("audit_log_path", "/app/hng-audit.log")

def write_audit(action: str, data: dict):
    """
    Write a structured entry to the audit log.

    Format:
      [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    ts        = datetime.utcnow().isoformat()
    ip        = data.get("ip", "global")
    condition = data.get("condition", "")
    rate      = data.get("rate", 0)
    baseline  = data.get("baseline", 0)
    duration  = data.get("duration", "")
    samples   = data.get("sample_count", "")
    mean      = data.get("effective_mean", "")
    stddev    = data.get("effective_stddev", "")

    if action == "BASELINE_RECALC":
        line = (
            f"[{ts}] BASELINE_RECALC "
            f"| mean={mean:.4f} "
            f"| stddev={stddev:.4f} "
            f"| samples={samples} "
            f"| source={data.get('source', '')}\n"
        )
    else:
        line = (
            f"[{ts}] {action} "
            f"ip={ip} "
            f"| condition={condition} "
            f"| rate={rate:.4f} "
            f"| baseline={baseline:.4f} "
            f"| duration={duration}\n"
        )

    # Write to file and stdout
    print(f"[audit] {line.strip()}")
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(line)
    except PermissionError:
        # Fallback path for local dev (no /var/log/nginx write access)
        fallback = os.path.join(os.path.dirname(__file__), "hng-audit.log")
        with open(fallback, "a") as f:
            f.write(line)


# ── Main ─────────────────────────────────────────────────────────────────────
def _resilient(fn, name: str):
    """
    Wraps a thread target so it automatically restarts on crash.
    Logs the error and waits 2 seconds before restarting.
    """
    def wrapper():
        while True:
            try:
                fn()
            except Exception as e:
                print(f"[main] ⚠️  Thread '{name}' crashed: {e} — restarting in 2s")
                time.sleep(2)
    return wrapper

def main():
    print("=" * 60)
    print("  HNG Anomaly Detection Engine — Starting")
    print(f"  Log path   : {cfg['log_path']}")
    print(f"  Dashboard  : http://0.0.0.0:{cfg['dashboard_port']}")
    print(f"  Audit log  : {AUDIT_LOG_PATH}")
    print("=" * 60)

    # ── 1. Notifier (Slack) ───────────────────────────────────────
    notifier = Notifier()
    notifier.start()

    # ── 2. Baseline calculator ────────────────────────────────────
    baseline = BaselineCalculator()

    # ── 3. Blocker (iptables) ─────────────────────────────────────
    blocker = Blocker(
        audit_callback  = write_audit,
        notify_callback = notifier.notify,
    )

    # ── 4. Anomaly Detector ───────────────────────────────────────
    def on_ip_anomaly(ip, rate, mean, stddev, reason):
        """
        Fired when a single IP exceeds the anomaly threshold.
        Bans the IP and tells the detector to stop watching it.
        """
        print(f"[main] ⚠️  IP anomaly: {ip} rate={rate:.2f} reason={reason}")
        banned = blocker.ban(
            ip      = ip,
            reason  = reason,
            rate    = rate,
            mean    = mean,
            stddev  = stddev,
        )
        if banned:
            # Stop detection firing again for this IP while it's banned
            detector.ban_ip(ip)

    def on_global_anomaly(rate, mean, stddev, reason):
        """
        Fired when global traffic spikes.
        No IP ban — Slack alert only.
        """
        print(f"[main] 🌐 Global anomaly: rate={rate:.2f} reason={reason}")
        notifier.notify("GLOBAL", {
            "condition": reason,
            "rate":      rate,
            "baseline":  mean,
            "stddev":    stddev,
            "timestamp": datetime.utcnow().isoformat(),
        })
        write_audit("GLOBAL_ANOMALY", {
            "condition": reason,
            "rate":      rate,
            "baseline":  mean,
        })

    detector = AnomalyDetector(
        baseline          = baseline,
        on_ip_anomaly     = on_ip_anomaly,
        on_global_anomaly = on_global_anomaly,
    )

    # ── 5. Unbanner ───────────────────────────────────────────────
    unbanner = Unbanner(
        blocker        = blocker,
        detector       = detector,
        audit_callback = write_audit,
    )

    # ── 6. Log monitor callback ───────────────────────────────────
    def on_log_entry(entry: dict):
        """
        Called for every parsed Nginx log line.
        Feeds all active modules.
        """
        baseline.record_request(entry["status"])
        detector.record_request(entry)

    # ── Start all background threads ──────────────────────────────
    threads = [
        threading.Thread(
            target = _resilient(lambda: tail_log(cfg["log_path"], on_log_entry), "monitor"),
            name   = "monitor",
            daemon = True,
        ),
        threading.Thread(
            target = _resilient(lambda: baseline.run_recalc_loop(audit_callback=write_audit), "baseline"),
            name   = "baseline",
            daemon = True,
        ),
        threading.Thread(
            target = _resilient(detector.run_detection_loop, "detector"),
            name   = "detector",
            daemon = True,
        ),
        threading.Thread(
            target = _resilient(unbanner.run_unban_loop, "unbanner"),
            name   = "unbanner",
            daemon = True,
        ),
    ]

    for t in threads:
        print(f"[main] Starting thread: {t.name}")
        t.start()

    print("[main] All threads running ✅")
    print(f"[main] Dashboard → http://0.0.0.0:{cfg['dashboard_port']}")

    # ── Dashboard runs on main thread (keeps process alive) ───────
    dashboard = Dashboard(
        detector = detector,
        blocker  = blocker,
        baseline = baseline,
    )
    dashboard.run()  # blocks here — process lives as long as Flask runs


if __name__ == "__main__":
    main()

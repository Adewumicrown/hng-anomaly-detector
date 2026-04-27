"""
dashboard.py — Live Metrics Web Dashboard

Serves a web UI at port 8080 showing:
  - Banned IPs
  - Global req/s
  - Top 10 source IPs
  - CPU/memory usage
  - Effective mean/stddev
  - Uptime

Auto-refreshes every 3 seconds via JavaScript.
Built with Flask — single file, no templates needed.
"""

import time
import psutil
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string
from config import cfg


# ── HTML template ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HNG Anomaly Detector — Live Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #e6edf3;
      min-height: 100vh;
      padding: 24px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      padding-bottom: 16px;
      border-bottom: 1px solid #21262d;
    }

    header h1 {
      font-size: 1.4rem;
      font-weight: 700;
      color: #58a6ff;
      letter-spacing: -0.3px;
    }

    #status-dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      background: #3fb950;
      display: inline-block;
      margin-right: 8px;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.4; }
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .card {
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 10px;
      padding: 20px;
    }

    .card .label {
      font-size: 0.75rem;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }

    .card .value {
      font-size: 2rem;
      font-weight: 700;
      color: #e6edf3;
    }

    .card .value.red   { color: #f85149; }
    .card .value.green { color: #3fb950; }
    .card .value.blue  { color: #58a6ff; }

    .section-title {
      font-size: 0.85rem;
      font-weight: 600;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin: 24px 0 12px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 10px;
      overflow: hidden;
      margin-bottom: 24px;
    }

    th {
      background: #21262d;
      color: #8b949e;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 10px 16px;
      text-align: left;
    }

    td {
      padding: 10px 16px;
      font-size: 0.88rem;
      border-top: 1px solid #21262d;
      color: #e6edf3;
    }

    tr:hover td { background: #1c2128; }

    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .badge.banned    { background: #3d1f1f; color: #f85149; }
    .badge.permanent { background: #2d1f3d; color: #d2a8ff; }
    .badge.active    { background: #1f3d2d; color: #3fb950; }

    .bar-wrap {
      background: #21262d;
      border-radius: 4px;
      height: 6px;
      width: 120px;
      display: inline-block;
      vertical-align: middle;
      margin-left: 8px;
    }

    .bar-fill {
      height: 100%;
      border-radius: 4px;
      background: #58a6ff;
    }

    footer {
      text-align: center;
      color: #484f58;
      font-size: 0.75rem;
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid #21262d;
    }

    #last-updated {
      font-size: 0.75rem;
      color: #484f58;
    }
  </style>
</head>
<body>

<header>
  <h1><span id="status-dot"></span>HNG Anomaly Detector</h1>
  <span id="last-updated">Connecting...</span>
</header>

<!-- Stat cards -->
<div class="grid">
  <div class="card">
    <div class="label">Global Req/s</div>
    <div class="value blue" id="global-rate">—</div>
  </div>
  <div class="card">
    <div class="label">Banned IPs</div>
    <div class="value red" id="banned-count">—</div>
  </div>
  <div class="card">
    <div class="label">Baseline Mean</div>
    <div class="value" id="mean">—</div>
  </div>
  <div class="card">
    <div class="label">Std Deviation</div>
    <div class="value" id="stddev">—</div>
  </div>
  <div class="card">
    <div class="label">CPU Usage</div>
    <div class="value" id="cpu">—</div>
  </div>
  <div class="card">
    <div class="label">Memory Usage</div>
    <div class="value" id="memory">—</div>
  </div>
  <div class="card">
    <div class="label">Uptime</div>
    <div class="value green" id="uptime">—</div>
  </div>
</div>

<!-- Banned IPs table -->
<div class="section-title">Banned IPs</div>
<table>
  <thead>
    <tr>
      <th>IP Address</th>
      <th>Reason</th>
      <th>Rate (req/s)</th>
      <th>Ban #</th>
      <th>Duration</th>
      <th>Banned At</th>
    </tr>
  </thead>
  <tbody id="banned-table">
    <tr><td colspan="6" style="color:#484f58">No banned IPs</td></tr>
  </tbody>
</table>

<!-- Top IPs table -->
<div class="section-title">Top 10 Source IPs (last 60s)</div>
<table>
  <thead>
    <tr>
      <th>IP Address</th>
      <th>Requests</th>
      <th>Activity</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody id="top-ips-table">
    <tr><td colspan="4" style="color:#484f58">No traffic yet</td></tr>
  </tbody>
</table>

<footer>
  HNG Anomaly Detection Engine &nbsp;·&nbsp; Refreshes every 3s
</footer>

<script>
  async function refresh() {
    try {
      const res  = await fetch('/api/metrics');
      const data = await res.json();

      // Stat cards
      document.getElementById('global-rate').textContent =
        data.global_rate.toFixed(2) + ' r/s';
      document.getElementById('banned-count').textContent =
        data.banned_count;
      document.getElementById('mean').textContent =
        data.mean.toFixed(2);
      document.getElementById('stddev').textContent =
        data.stddev.toFixed(2);
      document.getElementById('cpu').textContent =
        data.cpu_percent.toFixed(1) + '%';
      document.getElementById('memory').textContent =
        data.memory_percent.toFixed(1) + '%';
      document.getElementById('uptime').textContent =
        data.uptime;
      document.getElementById('last-updated').textContent =
        'Updated: ' + new Date().toLocaleTimeString();

      // Banned IPs table
      const bannedTbody = document.getElementById('banned-table');
      if (data.banned_ips.length === 0) {
        bannedTbody.innerHTML =
          '<tr><td colspan="6" style="color:#484f58">No banned IPs</td></tr>';
      } else {
        bannedTbody.innerHTML = data.banned_ips.map(b => `
          <tr>
            <td><code>${b.ip}</code></td>
            <td style="color:#8b949e;font-size:0.8rem">${b.reason}</td>
            <td>${b.rate.toFixed(2)}</td>
            <td>${b.ban_count}</td>
            <td><span class="badge ${b.duration === 'permanent' ? 'permanent' : 'banned'}">
              ${b.duration}
            </span></td>
            <td style="color:#8b949e">${b.banned_at}</td>
          </tr>
        `).join('');
      }

      // Top IPs table
      const topMax = data.top_ips.length > 0 ? data.top_ips[0][1] : 1;
      const topTbody = document.getElementById('top-ips-table');
      if (data.top_ips.length === 0) {
        topTbody.innerHTML =
          '<tr><td colspan="4" style="color:#484f58">No traffic yet</td></tr>';
      } else {
        topTbody.innerHTML = data.top_ips.map(([ip, count]) => {
          const pct     = Math.round((count / topMax) * 100);
          const isBanned = data.banned_ips.some(b => b.ip === ip);
          return `
            <tr>
              <td><code>${ip}</code></td>
              <td>${count}</td>
              <td>
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:${pct}%"></div>
                </div>
              </td>
              <td>
                <span class="badge ${isBanned ? 'banned' : 'active'}">
                  ${isBanned ? 'BANNED' : 'active'}
                </span>
              </td>
            </tr>
          `;
        }).join('');
      }

    } catch (e) {
      document.getElementById('last-updated').textContent = 'Error fetching metrics';
    }
  }

  // Refresh immediately then every 3 seconds
  refresh();
  setInterval(refresh, 3000);
</script>
</body>
</html>
"""


# ── Flask App ─────────────────────────────────────────────────────────────────

class Dashboard:
    def __init__(self, detector, blocker, baseline):
        """
        Args:
            detector: AnomalyDetector — for global rate + top IPs
            blocker:  Blocker         — for banned IP list
            baseline: BaselineCalculator — for mean/stddev
        """
        self.detector  = detector
        self.blocker   = blocker
        self.baseline  = baseline
        self.start_time = time.time()
        self.port      = cfg.get("dashboard_port", 8080)

        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            now          = time.time()
            mean, stddev = self.baseline.get_baseline()
            global_rate  = self.detector.get_global_rate()
            top_ips      = self.detector.get_top_ips(10)
            registry     = self.blocker.get_ban_registry()

            # Format banned IPs for the table
            banned_list = []
            for ip, entry in registry.items():
                ban_count = entry.get("ban_count", 1)
                banned_list.append({
                    "ip":        ip,
                    "reason":    entry.get("reason", ""),
                    "rate":      entry.get("rate", 0),
                    "ban_count": ban_count,
                    "duration":  self.blocker._get_ban_duration_label(ban_count),
                    "banned_at": datetime.fromtimestamp(
                        entry.get("banned_at", now),
                        tz=timezone.utc
                    ).strftime("%H:%M:%S UTC"),
                })

            # System metrics
            cpu_percent    = psutil.cpu_percent(interval=None)
            memory         = psutil.virtual_memory()
            uptime_seconds = int(now - self.start_time)
            uptime_str     = _format_uptime(uptime_seconds)

            return jsonify({
                "global_rate":     round(global_rate, 4),
                "banned_count":    len(banned_list),
                "banned_ips":      banned_list,
                "top_ips":         top_ips,
                "mean":            round(mean, 4),
                "stddev":          round(stddev, 4),
                "cpu_percent":     cpu_percent,
                "memory_percent":  memory.percent,
                "memory_used_mb":  round(memory.used / 1024 / 1024, 1),
                "uptime":          uptime_str,
                "timestamp":       datetime.utcnow().isoformat(),
            })

    def run(self):
        """Start the Flask server — runs in its own thread."""
        print(f"[dashboard] Starting on port {self.port}")
        # use_reloader=False is critical — reloader breaks threading
        self.app.run(
            host="0.0.0.0",
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )


def _format_uptime(seconds: int) -> str:
    """Convert seconds to human-readable uptime string."""
    days    = seconds // 86400
    hours   = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs    = seconds % 60

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"

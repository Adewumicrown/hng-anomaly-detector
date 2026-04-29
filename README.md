# HNG Anomaly Detection Engine

A real-time DDoS detection and mitigation daemon built for [cloud.ng](https://cloud.ng) — HNG's Nextcloud-powered cloud storage platform. The daemon watches all incoming HTTP traffic, learns what normal looks like, and automatically blocks IPs that deviate from the baseline — whether from a single aggressive attacker or a global traffic spike.

---

## Live Endpoints

| Resource | URL |
|---|---|
| **Metrics Dashboard** | http://3.144.234.143:8080 |
| **Server IP** | 3.144.234.143 |

> Nextcloud is accessible by IP only: http://3.144.234.143

---

## GitHub Repository

**https://github.com/Adewumicrown/hng-anomaly-detector**

---

## Blog Post

> https://dev.to/adewumicrown/building-a-self-learning-ddos-guard-4jd4

---

## Language Choice

**Python** — chosen for its readability, fast iteration speed, and excellent standard library support for threading, collections (deque), and subprocess. The `collections.deque` structure is a natural fit for sliding window operations, and Python's threading model is sufficient for I/O-bound workloads like log tailing and HTTP alerting.

---

## Architecture Overview

```
Internet Traffic
      │
      ▼
   Nginx (port 80)
   JSON access logs → /var/log/nginx/hng-access.log
      │                        │
      ▼                        ▼ (shared Docker volume: HNG-nginx-logs)
  Nextcloud              Detector Daemon
  (port 80 internal)          │
                         ┌────┴────────────────────┐
                         │                         │
                    monitor.py              baseline.py
                    (log tailer)        (rolling 30-min stats)
                         │                         │
                         └────────┬────────────────┘
                                  ▼
                            detector.py
                         (sliding window, z-score)
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
              blocker.py    notifier.py   dashboard.py
              (iptables)     (Slack)      (Flask UI)
                    │
              unbanner.py
              (backoff schedule)
```

---

## How the Sliding Window Works

The detector maintains two `deque`-based sliding windows covering the **last 60 seconds** — one global (all traffic) and one per-IP.

**Deque structure:**
Each entry in the deque is a Unix timestamp (`time.time()`) recorded when the request was parsed — not when Nginx logged it. Requests are always appended to the **right** of the deque in chronological order.

**Eviction logic:**
Every second, before computing the rate, the detector calculates a cutoff:
```python
cutoff = now - 60  # 60 seconds ago
```
It then pops entries from the **left** of the deque while the oldest entry is older than the cutoff:
```python
while window and window[0] < cutoff:
    window.popleft()
```
Since timestamps are always appended in order, the left side is always the oldest — making eviction O(k) where k is the number of expired entries, not O(n).

**Rate calculation:**
After eviction, the current rate is simply:
```python
rate = len(window) / window_seconds  # requests per second
```

This gives an accurate real-time view of requests in the last 60 seconds without any counters or approximations.

---

## How the Baseline Works

The baseline learns from a **30-minute rolling window** of per-second request counts.

**Window size:** 1800 seconds (30 minutes) of per-second counts stored in a deque.

**Hourly slots:** Counts are also stored in per-hour buckets (`{ hour_int: [counts] }`). The current hour's slot is preferred when it has enough data (`>= 10 samples`), falling back to the full 30-minute window otherwise.

**Recalculation interval:** Every 60 seconds, the daemon recomputes:
```
mean   = sum(counts) / len(counts)
stddev = sqrt(sum((x - mean)² for x in counts) / len(counts))
```

**Floor values:** Both `effective_mean` and `effective_stddev` have a minimum floor of `1.0` to prevent division-by-zero in z-score calculations and avoid false positives when traffic is near zero.

**Error rate baseline:** A separate baseline tracks 4xx/5xx error rates using the same 30-minute window, used to detect error surges per IP.

All baseline values are derived from real observed traffic — nothing is hardcoded.

---

## How Detection Makes a Decision

Every second the detector compares the current sliding window rate against the baseline using **two independent conditions** — whichever fires first triggers the response:

**Condition 1 — Z-score threshold:**
```
z = (current_rate - mean) / stddev
Fire if z > 3.0
```
This catches statistical anomalies — rates that are unusually far above the normal distribution.

**Condition 2 — Absolute multiplier:**
```
Fire if current_rate > 5.0 × mean
```
This catches floods even when the baseline is very low and stddev is small.

**Error surge tightening:**
If an IP's 4xx/5xx rate exceeds `3x` the baseline error rate, its detection thresholds are automatically tightened by 40% — making it easier to ban a misbehaving IP sooner.

**Global vs per-IP:**
- Per-IP anomaly → iptables DROP rule + Slack ban alert
- Global anomaly → Slack alert only (no single IP to ban)

---

## How iptables Blocks an IP

When a per-IP anomaly is detected, the blocker runs:
```bash
iptables -A INPUT -s <ip> -j DROP
```

This adds a rule to the kernel's INPUT chain that silently drops all packets from the offending IP — they never reach Nginx or Nextcloud. The rule is applied via Python's `subprocess.run()` within the detector container which runs with `NET_ADMIN` capability and `privileged: true`.

**Auto-unban backoff schedule:**
The unbanner checks every 30 seconds and releases bans on this schedule:

| Ban count | Duration |
|---|---|
| 1st ban | 10 minutes |
| 2nd ban | 30 minutes |
| 3rd ban | 2 hours |
| 4th+ ban | Permanent |

On unban, the rule is removed with:
```bash
iptables -D INPUT -s <ip> -j DROP
```

A Slack notification is sent on every ban and unban event.

---

## Repository Structure

```
hng-anomaly-detector/
├── detector/
│   ├── main.py           # Entry point — wires all threads together
│   ├── monitor.py        # Nginx log tailer — reads line by line
│   ├── baseline.py       # Rolling 30-min baseline calculator
│   ├── detector.py       # Sliding window anomaly detection engine
│   ├── blocker.py        # iptables ban/unban logic
│   ├── unbanner.py       # Auto-unban backoff loop
│   ├── notifier.py       # Slack alert sender (async queue)
│   ├── dashboard.py      # Flask live metrics UI
│   ├── config.py         # Config loader (config.yaml + .env)
│   ├── config.yaml       # All thresholds and settings
│   ├── requirements.txt  # Python dependencies
│   └── Dockerfile
├── nginx/
│   └── nginx.conf        # Reverse proxy + JSON log format
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
└── README.md
```

---

## Setup Instructions — Fresh VPS to Fully Running Stack

### 1. Provision a VPS

Minimum: 2 vCPU, 2GB RAM. Ubuntu 22.04 LTS recommended.
Open ports: 22 (SSH), 80 (HTTP), 8080 (Dashboard).

### 2. Install Docker and Docker Compose

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git iptables

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify
docker --version
docker-compose --version
```

### 3. Clone the Repository

```bash
git clone https://github.com/Adewumicrown/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 4. Configure Secrets

Create the `.env` file with your real Slack webhook URL:

```bash
cat > detector/.env << 'EOF'
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EOF
```

### 5. Review Configuration

All detection thresholds are in `detector/config.yaml`:

```yaml
log_path: /var/log/nginx/hng-access.log
sliding_window_seconds: 60
baseline_window_minutes: 30
baseline_recalc_interval_seconds: 60
baseline_min_samples: 10
zscore_threshold: 3.0
rate_multiplier_threshold: 5.0
error_surge_multiplier: 3.0
unban_schedule:
  - 600       # 10 minutes
  - 1800      # 30 minutes
  - 7200      # 2 hours
  - permanent
slack_webhook_url: "YOUR_SLACK_WEBHOOK_URL_HERE"
dashboard_port: 8080
audit_log_path: /app/hng-audit.log
```

### 6. Build and Start the Stack

```bash
docker-compose up --build -d
```

This starts three containers:
- `hng-nginx` — reverse proxy on port 80
- `hng-nextcloud` — Nextcloud application
- `hng-detector` — anomaly detection daemon on port 8080

### 7. Verify Everything is Running

```bash
# All containers up?
docker ps

# JSON logs being written?
docker exec hng-nginx tail -5 /var/log/nginx/hng-access.log

# Detector processing traffic?
docker logs hng-detector --tail 30

# Dashboard accessible?
curl http://localhost:8080
```

### 8. Test Detection

From a separate machine, send a flood of requests:
```bash
ab -n 5000 -c 100 http://<YOUR-SERVER-IP>/
```

Watch detection fire:
```bash
docker logs hng-detector --follow
sudo iptables -L INPUT -n
```

---

## Configuration Reference

| Parameter | Default | Description |
|---|---|---|
| `sliding_window_seconds` | 60 | Size of the per-IP and global sliding windows |
| `baseline_window_minutes` | 30 | Rolling history used to compute mean/stddev |
| `baseline_recalc_interval_seconds` | 60 | How often baseline is recalculated |
| `baseline_min_samples` | 10 | Minimum samples before baseline is trusted |
| `zscore_threshold` | 3.0 | Z-score above which traffic is anomalous |
| `rate_multiplier_threshold` | 5.0 | Rate multiple above mean that triggers detection |
| `error_surge_multiplier` | 3.0 | 4xx/5xx multiple that tightens per-IP thresholds |
| `dashboard_port` | 8080 | Port for the live metrics web UI |

---

## Screenshots

| Screenshot | Description |
|---|---|
| `Tool-running.png` | Daemon running, processing log lines |
| `Ban-slack.png` | Slack ban notification |
| `Unban-slack.png` | Slack unban notification |
| `Global-alert-slack.png` | Slack global anomaly notification |
| `Iptables-banned.png` | `sudo iptables -L -n` showing a blocked IP |
| `Audit-log.png` | Structured audit log with ban/unban/baseline entries |
| `Baseline-graph.png` | Baseline over time showing hourly slot differences |

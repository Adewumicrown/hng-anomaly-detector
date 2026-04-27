"""
notifier.py — Slack Alert Sender

Sends structured alerts to Slack for:
  - BAN: per-IP anomaly detected and blocked
  - UNBAN: IP released from ban
  - GLOBAL: global traffic spike (no ban, alert only)

All alerts include: condition, current rate, baseline, timestamp,
and ban duration where applicable.

Uses a background queue so alerts never block the detection loop.
"""

import requests
import threading
import queue
import time
from datetime import datetime
from config import cfg


class Notifier:
    def __init__(self):
        self.webhook_url = cfg.get("slack_webhook_url", "")

        # Background queue so Slack calls never block detection
        self._queue: queue.Queue = queue.Queue()
        self._lock  = threading.Lock()

        if not self.webhook_url or self.webhook_url == "YOUR_SLACK_WEBHOOK_URL_HERE":
            print("[notifier] WARNING: No Slack webhook URL configured — alerts will be logged only")

    def _format_ban_message(self, data: dict) -> dict:
        """Format a BAN alert as a Slack block message."""
        return {
            "text": f"🚨 *IP BANNED* — `{data.get('ip')}`",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 IP BANNED — Anomaly Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{data.get('ip')}`"},
                        {"type": "mrkdwn", "text": f"*Condition:*\n{data.get('condition')}"},
                        {"type": "mrkdwn", "text": f"*Current Rate:*\n{data.get('rate', 0):.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{data.get('baseline', 0):.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Std Deviation:*\n{data.get('stddev', 0):.2f}"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n{data.get('duration', 'unknown')}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"⏰ {data.get('timestamp', datetime.utcnow().isoformat())}"
                        }
                    ]
                }
            ]
        }

    def _format_unban_message(self, data: dict) -> dict:
        """Format an UNBAN alert as a Slack block message."""
        return {
            "text": f"✅ *IP UNBANNED* — `{data.get('ip')}`",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ IP UNBANNED — Ban Released"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{data.get('ip')}`"},
                        {"type": "mrkdwn", "text": f"*Ban Count:*\n{data.get('ban_count', 1)}"},
                        {"type": "mrkdwn", "text": f"*Duration Served:*\n{data.get('duration', 'unknown')}"},
                        {"type": "mrkdwn", "text": f"*Next Ban Duration:*\n{_next_ban_label(data.get('ban_count', 1))}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"⏰ {data.get('timestamp', datetime.utcnow().isoformat())}"
                        }
                    ]
                }
            ]
        }

    def _format_global_message(self, data: dict) -> dict:
        """Format a GLOBAL anomaly alert as a Slack block message."""
        return {
            "text": "⚠️ *GLOBAL TRAFFIC SPIKE* — Anomaly Detected",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ GLOBAL TRAFFIC SPIKE"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Condition:*\n{data.get('condition')}"},
                        {"type": "mrkdwn", "text": f"*Global Rate:*\n{data.get('rate', 0):.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{data.get('baseline', 0):.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Std Deviation:*\n{data.get('stddev', 0):.2f}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "ℹ️ No IP banned — global spike affects all traffic. Monitor closely."
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"⏰ {data.get('timestamp', datetime.utcnow().isoformat())}"
                        }
                    ]
                }
            ]
        }

    def _send(self, payload: dict):
        """
        Send a payload to Slack webhook.
        Retries once on failure with a 2s delay.
        """
        if not self.webhook_url or self.webhook_url == "YOUR_SLACK_WEBHOOK_URL_HERE":
            # No webhook — just print to stdout
            print(f"[notifier] [NO WEBHOOK] Alert: {payload.get('text')}")
            return

        for attempt in range(2):
            try:
                resp = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=5
                )
                if resp.status_code == 200:
                    print(f"[notifier] Slack alert sent: {payload.get('text', '')[:60]}")
                    return
                else:
                    print(f"[notifier] Slack returned {resp.status_code}: {resp.text}")

            except requests.RequestException as e:
                print(f"[notifier] Slack request failed (attempt {attempt+1}): {e}")

            if attempt == 0:
                time.sleep(2)

        print(f"[notifier] Failed to send alert after 2 attempts")

    def _worker(self):
        """
        Background thread — drains the alert queue and sends to Slack.
        Decoupled from detection loop so a slow Slack API never delays banning.
        """
        while True:
            try:
                payload = self._queue.get(timeout=1)
                self._send(payload)
                self._queue.task_done()
            except queue.Empty:
                continue

    def start(self):
        """Start the background sender thread."""
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()
        print("[notifier] Slack alert worker started")

    def notify(self, event: str, data: dict):
        """
        Public method — called by blocker and detector.
        Enqueues the alert for async sending.

        event: "BAN" | "UNBAN" | "GLOBAL"
        """
        if event == "BAN":
            payload = self._format_ban_message(data)
        elif event == "UNBAN":
            payload = self._format_unban_message(data)
        elif event == "GLOBAL":
            payload = self._format_global_message(data)
        else:
            print(f"[notifier] Unknown event type: {event}")
            return

        # Always log to stdout regardless of Slack
        print(f"[notifier] Queuing {event} alert for {data.get('ip', 'global')}")
        self._queue.put(payload)


def _next_ban_label(current_ban_count: int) -> str:
    """Helper — what duration will the NEXT ban be?"""
    schedule = cfg.get("unban_schedule", [600, 1800, 7200, "permanent"])
    next_index = min(current_ban_count, len(schedule) - 1)
    val = schedule[next_index]
    if val == "permanent":
        return "permanent"
    minutes = val // 60
    if minutes >= 60:
        return f"{minutes // 60}h"
    return f"{minutes}min"

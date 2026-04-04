"""
utils/notify.py — ReconNinja v7.0.0
Notification hooks — fire alerts mid-scan when critical/high findings arrive.

Supported:
  --notify slack://hooks.slack.com/services/xxx    (Slack Incoming Webhook)
  --notify discord://discord.com/api/webhooks/xxx  (Discord Webhook)
  --notify https://your-server.com/webhook         (Generic JSON POST)

Called by orchestrator at end of critical phases.
Thread-safe — safe to call from threaded nmap workers.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

from utils.logger import log, safe_print

_NOTIFY_LOCK = threading.Lock()


@dataclass
class NotifyEvent:
    scan_target:  str
    phase:        str
    severity:     str   # critical | high | medium | info
    title:        str
    detail:       str
    count:        int = 1


# ── URL normalisation ─────────────────────────────────────────────────────────

def _normalise_url(url: str) -> tuple[str, str]:
    """
    Returns (provider, real_url).
    Converts slack:// and discord:// pseudo-schemes to https://.
    """
    if url.startswith("slack://"):
        return "slack", "https://" + url[len("slack://"):]
    if url.startswith("discord://"):
        return "discord", "https://" + url[len("discord://"):]
    return "generic", url


# ── Payload builders ──────────────────────────────────────────────────────────

def _slack_payload(event: NotifyEvent) -> dict:
    colour = {"critical": "#ff4444", "high": "#ff8800",
               "medium": "#ffcc00", "info": "#888888"}.get(event.severity, "#888888")
    return {
        "attachments": [{
            "color": colour,
            "title": f"ReconNinja [{event.severity.upper()}] — {event.scan_target}",
            "text":  f"*Phase:* {event.phase}\n*{event.title}*\n{event.detail}",
            "footer": "ReconNinja v7.0.0",
        }]
    }


def _discord_payload(event: NotifyEvent) -> dict:
    colour_int = {
        "critical": 0xFF4444, "high": 0xFF8800,
        "medium":   0xFFCC00, "info": 0x888888,
    }.get(event.severity, 0x888888)
    return {
        "embeds": [{
            "title":       f"[{event.severity.upper()}] {event.title}",
            "description": f"**Target:** {event.scan_target}\n**Phase:** {event.phase}\n{event.detail}",
            "color":       colour_int,
            "footer":      {"text": "ReconNinja v7.0.0"},
        }]
    }


def _generic_payload(event: NotifyEvent) -> dict:
    return {
        "tool":    "ReconNinja",
        "version": "7.0.0",
        "target":  event.scan_target,
        "phase":   event.phase,
        "severity": event.severity,
        "title":   event.title,
        "detail":  event.detail,
        "count":   event.count,
    }


# ── HTTP send ─────────────────────────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 10) -> bool:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ReconNinja/7.0.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except urllib.error.HTTPError as e:
        log.warning(f"Notify HTTP error {e.code}: {url}")
        return False
    except Exception as e:
        log.debug(f"Notify send failed: {e}")
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def send_notification(
    notify_url: str,
    event: NotifyEvent,
    timeout: int = 10,
    silent: bool = True,
) -> bool:
    """
    Send a notification for a scan event.
    Thread-safe — can be called from any phase or worker thread.

    Args:
        notify_url: Slack/Discord/webhook URL (--notify flag)
        event:      the event to report
        timeout:    HTTP timeout
        silent:     if True, swallow all errors silently (default)

    Returns:
        True if notification was sent successfully
    """
    if not notify_url:
        return False

    with _NOTIFY_LOCK:
        try:
            provider, real_url = _normalise_url(notify_url)
            if provider == "slack":
                payload = _slack_payload(event)
            elif provider == "discord":
                payload = _discord_payload(event)
            else:
                payload = _generic_payload(event)

            ok = _post(real_url, payload, timeout)
            if ok and not silent:
                safe_print(f"[dim]Notification sent → {provider}[/]")
            return ok
        except Exception as e:
            if not silent:
                log.warning(f"Notification failed: {e}")
            return False


def notify_finding(
    notify_url: Optional[str],
    target: str,
    phase: str,
    severity: str,
    title: str,
    detail: str = "",
    count: int = 1,
) -> None:
    """Convenience wrapper — no-op if notify_url is empty."""
    if not notify_url:
        return
    event = NotifyEvent(
        scan_target=target,
        phase=phase,
        severity=severity,
        title=title,
        detail=detail,
        count=count,
    )
    send_notification(notify_url, event)

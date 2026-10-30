"""
notifier.py
============
Simulated alert notifications - NO real email/SMS is sent. When an
event's severity crosses the CRITICAL threshold, we build a
realistic-looking message object (recipient, channel, subject, body,
sent_at) and hand it back to test_engine.py to store, purely for
dashboard display ("what a real ops inbox would have received").
"""

from datetime import datetime

RECIPIENTS = {
    "email": "grid-admin@utility.local",
    "sms": "+968-XXXX-OPS",
}

NOTIFY_THRESHOLD_BANDS = ("CRITICAL",)


def should_notify(severity_band):
    return severity_band in NOTIFY_THRESHOLD_BANDS


def build_notification(attack_name, node_name, severity_band, confidence):
    now = datetime.now().strftime("%H:%M:%S")
    subject = f"{severity_band}: {attack_name} on {node_name}"
    body = (
        f"Automated IDS alert. {attack_name} detected on {node_name} "
        f"with {round(confidence*100)}% model confidence. Severity classified as "
        f"{severity_band}. Automated mitigation has been engaged; no operator "
        f"action required unless RESOLVED is not reached within the expected window."
    )
    return {
        "channel": "email",
        "recipient": RECIPIENTS["email"],
        "subject": subject,
        "body": body,
        "sent_at": now,
        "severity": severity_band,
    }

"""
SIEM Dashboard - Python Backend (Flask API)
Serves security event data, alerts, and threat intelligence.
Run: pip install flask flask-cors && python app.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import random
import uuid
import json

app = Flask(__name__)
CORS(app)

# ─── Simulated Data Store ────────────────────────────────────────────────────

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
EVENT_TYPES = [
    "Brute Force Attempt", "Malware Detected", "Port Scan",
    "Privilege Escalation", "Data Exfiltration", "Phishing Email",
    "Unauthorized Access", "DDoS Attack", "SQL Injection",
    "XSS Attack", "Ransomware", "Insider Threat",
    "DNS Tunneling", "C2 Communication", "Lateral Movement"
]
SOURCES = [
    "Firewall", "IDS/IPS", "Endpoint", "Email Gateway",
    "WAF", "DNS Server", "SIEM Correlation", "Cloud Security",
    "Active Directory", "VPN Gateway"
]
STATUS_OPTIONS = ["open", "investigating", "resolved", "false_positive"]
THREAT_ACTORS = [
    "APT28", "Lazarus Group", "APT41", "Turla",
    "Sandworm", "Cozy Bear", "Unknown", "Internal"
]
NETWORK_ZONES = ["DMZ", "Internal", "External", "Cloud", "VPN"]


def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_event(event_id=None, hours_ago_max=72):
    timestamp = datetime.now() - timedelta(
        hours=random.randint(0, hours_ago_max),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    severity = random.choices(
        SEVERITY_LEVELS,
        weights=[5, 15, 30, 30, 20],
        k=1
    )[0]
    return {
        "id": event_id or str(uuid.uuid4())[:8],
        "timestamp": timestamp.isoformat(),
        "event_type": random.choice(EVENT_TYPES),
        "severity": severity,
        "source": random.choice(SOURCES),
        "source_ip": generate_ip(),
        "dest_ip": generate_ip(),
        "status": random.choice(STATUS_OPTIONS),
        "threat_actor": random.choice(THREAT_ACTORS) if severity in ["critical", "high"] else "Unknown",
        "network_zone": random.choice(NETWORK_ZONES),
        "description": f"Suspicious activity detected from endpoint",
        "risk_score": random.randint(
            70 if severity == "critical" else 40 if severity == "high" else 10,
            100 if severity == "critical" else 70 if severity == "high" else 50
        )
    }


# Pre-generate a pool of events
EVENT_POOL = sorted(
    [generate_event(f"EVT-{i:04d}") for i in range(200)],
    key=lambda x: x["timestamp"],
    reverse=True
)


# ─── API Routes ──────────────────────────────────────────────────────────────

@app.route("/api/events", methods=["GET"])
def get_events():
    """Get security events with optional filtering."""
    severity = request.args.get("severity")
    source = request.args.get("source")
    status = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    filtered = EVENT_POOL[:]
    if severity:
        filtered = [e for e in filtered if e["severity"] == severity]
    if source:
        filtered = [e for e in filtered if e["source"] == source]
    if status:
        filtered = [e for e in filtered if e["status"] == status]

    return jsonify({
        "total": len(filtered),
        "events": filtered[offset:offset + limit]
    })


@app.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id):
    """Get a single event by ID."""
    for event in EVENT_POOL:
        if event["id"] == event_id:
            return jsonify(event)
    return jsonify({"error": "Event not found"}), 404


@app.route("/api/dashboard/summary", methods=["GET"])
def dashboard_summary():
    """Get dashboard summary statistics."""
    now = datetime.now()
    last_24h = [
        e for e in EVENT_POOL
        if datetime.fromisoformat(e["timestamp"]) > now - timedelta(hours=24)
    ]

    severity_counts = {}
    for level in SEVERITY_LEVELS:
        severity_counts[level] = len([e for e in last_24h if e["severity"] == level])

    source_counts = {}
    for event in last_24h:
        src = event["source"]
        source_counts[src] = source_counts.get(src, 0) + 1

    status_counts = {}
    for event in last_24h:
        s = event["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    return jsonify({
        "total_events_24h": len(last_24h),
        "critical_alerts": severity_counts.get("critical", 0),
        "high_alerts": severity_counts.get("high", 0),
        "open_incidents": status_counts.get("open", 0) + status_counts.get("investigating", 0),
        "resolved_incidents": status_counts.get("resolved", 0),
        "severity_breakdown": severity_counts,
        "source_breakdown": source_counts,
        "status_breakdown": status_counts,
        "avg_risk_score": round(
            sum(e["risk_score"] for e in last_24h) / max(len(last_24h), 1), 1
        ),
        "top_threat_actors": _count_field(last_24h, "threat_actor", top=5),
        "top_event_types": _count_field(last_24h, "event_type", top=5)
    })


@app.route("/api/dashboard/timeline", methods=["GET"])
def dashboard_timeline():
    """Get event counts over time for charting."""
    hours = int(request.args.get("hours", 24))
    now = datetime.now()
    buckets = []

    for h in range(hours, 0, -1):
        bucket_start = now - timedelta(hours=h)
        bucket_end = now - timedelta(hours=h - 1)
        events_in_bucket = [
            e for e in EVENT_POOL
            if bucket_start <= datetime.fromisoformat(e["timestamp"]) < bucket_end
        ]
        buckets.append({
            "hour": bucket_start.strftime("%H:%M"),
            "total": len(events_in_bucket),
            "critical": len([e for e in events_in_bucket if e["severity"] == "critical"]),
            "high": len([e for e in events_in_bucket if e["severity"] == "high"]),
            "medium": len([e for e in events_in_bucket if e["severity"] == "medium"]),
            "low": len([e for e in events_in_bucket if e["severity"] == "low"]),
        })

    return jsonify({"timeline": buckets})


@app.route("/api/alerts/active", methods=["GET"])
def active_alerts():
    """Get currently active/unresolved alerts."""
    active = [
        e for e in EVENT_POOL
        if e["status"] in ["open", "investigating"]
        and e["severity"] in ["critical", "high"]
    ]
    return jsonify({
        "count": len(active),
        "alerts": sorted(active, key=lambda x: x["risk_score"], reverse=True)[:20]
    })


@app.route("/api/threats/map", methods=["GET"])
def threat_map():
    """Get geographic threat data (simulated)."""
    countries = [
        {"name": "Russia", "lat": 55.75, "lng": 37.62, "attacks": random.randint(20, 80)},
        {"name": "China", "lat": 39.90, "lng": 116.40, "attacks": random.randint(30, 90)},
        {"name": "North Korea", "lat": 39.03, "lng": 125.75, "attacks": random.randint(10, 40)},
        {"name": "Iran", "lat": 35.69, "lng": 51.39, "attacks": random.randint(5, 30)},
        {"name": "Brazil", "lat": -15.79, "lng": -47.88, "attacks": random.randint(5, 25)},
        {"name": "USA", "lat": 38.90, "lng": -77.04, "attacks": random.randint(15, 50)},
        {"name": "India", "lat": 28.61, "lng": 77.21, "attacks": random.randint(10, 35)},
        {"name": "Germany", "lat": 52.52, "lng": 13.41, "attacks": random.randint(5, 20)},
    ]
    return jsonify({"threats": countries})


@app.route("/api/events/<event_id>/status", methods=["PATCH"])
def update_event_status(event_id):
    """Update the status of an event."""
    data = request.get_json()
    new_status = data.get("status")
    if new_status not in STATUS_OPTIONS:
        return jsonify({"error": "Invalid status"}), 400

    for event in EVENT_POOL:
        if event["id"] == event_id:
            event["status"] = new_status
            return jsonify(event)

    return jsonify({"error": "Event not found"}), 404


def _count_field(events, field, top=5):
    counts = {}
    for e in events:
        val = e[field]
        counts[val] = counts.get(val, 0) + 1
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"name": k, "count": v} for k, v in sorted_counts[:top]]


if __name__ == "__main__":
    print("🛡️  SIEM Dashboard API running on http://localhost:5000")
    app.run(debug=True, port=5000)

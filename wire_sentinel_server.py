"""
Wire Sentinel Pro
Advanced Real-Time Network Leak Monitor
"""

from flask import Flask, jsonify, send_from_directory, request
from collections import deque, Counter
from datetime import datetime
import threading
import re
import math
import json
import os
from scapy.all import sniff, IP, TCP, UDP, Raw

# ==============================
# CONFIG
# ==============================

INTERFACE = "wlan0"
PACKET_BUFFER = 1000
ALERT_BUFFER = 500
EXPORT_DIR = "exports"

if not os.path.exists(EXPORT_DIR):
    os.makedirs(EXPORT_DIR)

# ==============================
# INIT
# ==============================

app = Flask(__name__)

packets = deque(maxlen=PACKET_BUFFER)
alerts = deque(maxlen=ALERT_BUFFER)
lock = threading.Lock()

stats = {
    "total_packets": 0,
    "suspicious_packets": 0
}

# ==============================
# THREAT ENGINE
# ==============================

SUSPICIOUS_PATTERNS = [
    r'password[=:]\S+',
    r'api[_-]?key[=:]\S+',
    r'token[=:]\S+',
    r'Bearer\s+[A-Za-z0-9\-\._]+',
    r'AKIA[0-9A-Z]{16}',
]

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    length = len(data)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy

def analyze_payload(payload):
    score = 0.0
    matches = []

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            score += 0.4
            matches.append(pattern)

    if len(payload) > 30 and shannon_entropy(payload) > 5.5:
        score += 0.3

    return {
        "suspicious": score > 0,
        "confidence": min(score, 1.0),
        "patterns": matches
    }

def analyze_file_content(filepath):
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    with open(filepath, "r", errors="ignore") as f:
        content = f.read()

    entropy = shannon_entropy(content)
    length = len(content)

    risk = 0
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            risk += 1

    rating = "LOW"
    if risk >= 2 or entropy > 5.8:
        rating = "HIGH"
    elif risk == 1 or entropy > 5.0:
        rating = "MEDIUM"

    return {
        "length": length,
        "entropy": round(entropy, 3),
        "risk_score": risk,
        "rating": rating
    }

# ==============================
# PACKET PROCESSOR
# ==============================

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    protocol = "OTHER"
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"

    payload = ""
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
        except:
            payload = ""

    analysis = analyze_payload(payload)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "source": ip.src,
        "destination": ip.dst,
        "protocol": protocol,
        "length": len(packet),
        "payload_preview": payload[:300],
        "suspicious": analysis["suspicious"],
        "confidence": analysis["confidence"]
    }

    with lock:
        packets.appendleft(entry)
        stats["total_packets"] += 1
        if analysis["suspicious"]:
            stats["suspicious_packets"] += 1
            alerts.appendleft(entry)

# ==============================
# SNIFFER
# ==============================

def start_sniffer():
    print(f"[+] Sniffing on {INTERFACE}")
    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False,
        filter="ip"
    )

# ==============================
# ANALYTICS
# ==============================

def top_destinations():
    with lock:
        return Counter(p["destination"] for p in packets).most_common(5)

def top_sources():
    with lock:
        return Counter(p["source"] for p in packets).most_common(5)

# ==============================
# EXPORT LOGS
# ==============================

@app.route("/api/export_logs", methods=["POST"])
def export_logs():
    data = request.json
    start = data.get("start")
    end = data.get("end")

    if not start or not end:
        return jsonify({"error": "Start and end time required"})

    with lock:
        filtered = [
            p for p in packets
            if start <= p["timestamp"] <= end
        ]

    now = datetime.now()
    filename = f"{EXPORT_DIR}/logs_{now.strftime('%Y-%m-%d')}_{now.strftime('%H-%M-%S')}.json"

    with open(filename, "w") as f:
        json.dump(filtered, f, indent=2)

    return jsonify({"saved_as": filename, "count": len(filtered)})

# ==============================
# ROUTES
# ==============================

@app.route("/")
def index():
    return send_from_directory(".", "wire_sentinel_dashboard.html")

@app.route("/api/live_packets")
def api_packets():
    with lock:
        return jsonify(list(packets))

@app.route("/api/stats")
def api_stats():
    with lock:
        return jsonify(stats)

@app.route("/api/top_destinations")
def api_top_dest():
    return jsonify(top_destinations())

@app.route("/api/top_sources")
def api_top_src():
    return jsonify(top_sources())

@app.route("/api/analyze_file")
def api_analyze_file():
    filepath = request.args.get("path")
    return jsonify(analyze_file_content(filepath))

# ==============================
# MAIN
# ==============================

if __name__ == "__main__":
    print("[+] Wire Sentinel Pro Starting...")
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, threaded=True)

from flask import Flask, jsonify, send_file
import threading
import sqlite3
import os
from predictor import start_sniffing, get_threat_logs

from flask_cors import CORS

app = Flask(__name__)
CORS(app)

sniffer_thread = None
sniffer_running = False

@app.route("/start-sniffer")
def start_sniffer():
    global sniffer_thread, sniffer_running
    if not sniffer_running:
        sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniffer_thread.start()
        sniffer_running = True
        return jsonify({"status": "sniffer started"})
    return jsonify({"status": "already running"})

@app.route("/logs")
def logs():
    conn = sqlite3.connect("threat_log.db")
    c = conn.cursor()
    c.execute("""
        SELECT * FROM (
            SELECT * FROM threats ORDER BY id DESC LIMIT 50
        ) sub
        ORDER BY id ASC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)



@app.route("/download-pcap")
def download_pcap():
    path = "output/suspicious_output.pcap"
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "PCAP file not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

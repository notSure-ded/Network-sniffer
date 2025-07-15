import scapy.all as scapy
import sqlite3
import requests
import geoip2.database
import joblib
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.utils import wrpcap
import pandas as pd
import threading


model = joblib.load("model/threat_model.pkl")


geoip_reader = geoip2.database.Reader("MMDB/GeoLite2-City.mmdb")


VT_API_KEY = "6c8b82c5b34b023eb3eac2d9fb5164b4aefce5ed9f0be8b25a95a405e22944c4"
VT_HEADERS = {"x-apikey": VT_API_KEY}


suspicious_packets = []


def init_db():
    conn = sqlite3.connect("threat_log.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        reason TEXT,
        country TEXT,
        city TEXT)''')
    conn.commit()
    conn.close()

init_db()


def start_sniffing():
    import threading
    thread = threading.Thread(target=main, daemon=True)
    thread.start()

def get_threat_logs():
    import sqlite3
    conn = sqlite3.connect("threat_log.db")
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return rows

def log_threat(src_ip, dst_ip, reason, country, city):
    conn = sqlite3.connect("threat_log.db")
    c = conn.cursor()
    c.execute("INSERT INTO threats (timestamp, src_ip, dst_ip, reason, country, city) VALUES (?, ?, ?, ?, ?, ?)",
              (time.ctime(), src_ip, dst_ip, reason, country, city))
    conn.commit()
    conn.close()

def get_geoip_info(ip):
    try:
        response = geoip_reader.city(ip)
        return response.country.name, response.city.name
    except:
        return "Unknown", "Unknown"

def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=VT_HEADERS, timeout=5)
        data = response.json()
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return True
    except:
        pass
    return False

def extract_features(pkt):
    return [
        len(pkt),
        int(pkt.haslayer("Raw")),
        int(pkt.haslayer("DNS")),
        int(pkt.haslayer("TCP")),
        int(pkt.haslayer("UDP")),
        int(pkt.haslayer("ICMP")),
        pkt.sport if hasattr(pkt, 'sport') else 0,
        pkt.dport if hasattr(pkt, 'dport') else 0,
        pkt["TCP"].flags.value if pkt.haslayer("TCP") else 0  # 🔥 KEY FIX
    ]



def encode_flags(flags):
    flag_str = str(flags)
    flag_map = {"F":1, "S":2, "R":3, "P":4, "A":5, "U":6}
    value = 0
    for char in flag_str:
        value += flag_map.get(char, 0)
    return value

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        try:
            features = extract_features(packet)

            feature_names = [
                "length", "has_raw", "has_dns", "has_tcp", "has_udp",
                "has_icmp", "src_port", "dst_port", "flags"
            ]
            df_features = pd.DataFrame([features], columns=feature_names)

            prediction = model.predict(df_features)[0]
            prob = model.predict_proba(df_features)[0][prediction]
            label = "suspicious" if prediction == 1 else "normal"

            already_logged = False

           
            if prediction >= 0.9:
                country, city = get_geoip_info(src_ip)
                log_threat(src_ip, dst_ip, "ML: Suspicious pattern", country, city)
                suspicious_packets.append(packet)
                print(f"[ML] Suspicious: {src_ip} -> {dst_ip} ({country}, {city})")
                already_logged = True

            
            if check_virustotal(src_ip) and not already_logged:
                country, city = get_geoip_info(src_ip)
                log_threat(src_ip, dst_ip, "VirusTotal: Malicious IP", country, city)
                suspicious_packets.append(packet)
                print(f"[VT] Malicious IP: {src_ip} -> {dst_ip} ({country}, {city})")
                already_logged = True

            
            if prob >= 0.8:
                print(f"[ML] {src_ip} -> {dst_ip} | Predicted: {label} | Confidence: {prob:.2f} Predection : {prediction: .2f}" )

        except Exception as e:
            print(f"[!] Error: {e}")


import signal
running = True  


def signal_handler(sig, frame):
    global running
    print("\n[!] Ctrl+C detected. Stopping sniffing...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
def save_pcap_periodically(interval=60):
    while running:
        if suspicious_packets:
            filename = f"output/suspicious_autosave_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
            wrpcap(filename, suspicious_packets)
            print(f"[AutoSave] Saved suspicious packets to {filename}")
            suspicious_packets.clear()
        time.sleep(interval)

def main():
    print("[+] Sniffing started. Press Ctrl+C to stop.")
    
    # Start auto-save thread
    threading.Thread(target=save_pcap_periodically, daemon=True).start()
    
    try:
        while running:
            scapy.sniff(prn=process_packet, timeout=5, store=False)
    except Exception as e:
        print(f"[!] Error in sniff loop: {e}")
    
    # Final save
    if suspicious_packets:
        filename = f"output/suspicious_{time.strftime('%Y%m%d_%H%M%S')}_final.pcap"
        wrpcap(filename, suspicious_packets)
        print(f"[+] Final packets saved to {filename}")
    else:
        print("[*] No suspicious packets to save.")
    print("[*] Sniffer stopped cleanly.")



if __name__ == "__main__":
    main()

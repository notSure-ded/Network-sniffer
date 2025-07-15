# generate_dataset.py
from scapy.all import rdpcap
import pandas as pd

def extract_features(pkt):
    features = {
        "length": len(pkt),
        "has_raw": int(pkt.haslayer("Raw")),
        "has_dns": int(pkt.haslayer("DNS")),
        "has_tcp": int(pkt.haslayer("TCP")),
        "has_udp": int(pkt.haslayer("UDP")),
        "has_icmp": int(pkt.haslayer("ICMP")),
        "src_port": pkt.sport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0,
        "dst_port": pkt.dport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0,
        "flags": str(pkt["TCP"].flags) if pkt.haslayer("TCP") else "None"
    }
    return features

# Load a PCAP file you captured
packets = rdpcap("capture.pcap")  # Replace with your file
data = []
for pkt in packets:
    try:
        data.append(extract_features(pkt))
    except:
        continue

df = pd.DataFrame(data)

# 🛑 Manually label some rows as 'normal' or 'suspicious'
df["label"] = ["normal"] * (len(df) // 2) + ["suspicious"] * (len(df) - len(df) // 2)

df.to_csv("packet_dataset.csv", index=False)
print("Dataset saved as packet_dataset.csv")

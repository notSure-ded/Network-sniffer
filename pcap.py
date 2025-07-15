# sniff_to_pcap.py
from scapy.all import sniff, wrpcap

print("Sniffing for 30 packets...")

packets = sniff(count=30)  # or sniff(timeout=10)
wrpcap("capture.pcap", packets)

print("Packets saved to capture.pcap")

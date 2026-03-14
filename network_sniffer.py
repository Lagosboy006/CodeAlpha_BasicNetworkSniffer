from scapy.all import *
from datetime import datetime
import signal
import sys

print("🔍 CodeAlpha Cyber Security Internship")
print("   TASK 1: Basic Network Sniffer (with .pcap saving)\n")
print("Press Ctrl + C to stop and save packets\n")

packets = []

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] ", end="")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"Src: {src:15} → Dst: {dst:15}", end=" ")

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"Protocol: {proto}  Ports: {sport} → {dport}", end=" ")
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"Protocol: {proto}  Ports: {sport} → {dport}", end=" ")
        elif ICMP in packet:
            print("Protocol: ICMP", end=" ")
        else:
            print("Protocol: Other", end=" ")

        if Raw in packet:
            payload_len = len(packet[Raw].load)
            print(f" | Payload: {payload_len} bytes")
        else:
            print()
    else:
        print("Non-IP packet")

    packets.append(packet)
    print("-" * 90)

# Ctrl + C handler (guarantees save)
def signal_handler(sig, frame):
    filename = f"captured_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(filename, packets)
    print(f"\n\n Sniffing stopped!")
    print(f" {len(packets)} packets saved to → {filename}")
    print(" Tip: Open this .pcap file in Wireshark for full analysis!")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ================== START SNIFFING ==================
try:
    print("Available network interfaces:")
    print(get_if_list())
    
    iface = input("\nEnter interface to sniff (press Enter for default): ").strip()
    if not iface:
        iface = conf.iface

    print(f"\n🚀 Sniffing started on interface: {iface}")
    print("Capturing live packets... (Ctrl+C to stop)\n")

    sniff(iface=iface, prn=packet_callback, store=False, count=0)

except PermissionError:
    print("\n❌ Permission denied! (already using sudo)")
except Exception as e:
    print(f"\nError: {e}")

# CodeAlpha Cyber Security Internship - Task 1
**Basic Network Sniffer with .pcap Export**

## Project Overview
Built a real-time network packet sniffer using Python and Scapy as part of CodeAlpha Cyber Security Internship (March 2026).

## Features Implemented
- Captures live network traffic on chosen interface
- Displays Source/Destination IP, Protocol (TCP/UDP/ICMP), Ports, and Payload size
- Automatically saves all captured packets to a timestamped `.pcap` file
- Can be opened in Wireshark for deep analysis

## Technologies Used
- Python
- Scapy

## How to Run
```bash
sudo python3 network_sniffer.py
Choose interface (eth0) → Press Ctrl+C to stop and auto-save .pcap

#!/usr/bin/env python3
"""
CodeAlpha Task 1 - Basic Network Sniffer
Captures packets with scapy and prints source/destination IPs,
protocol, ports and a payload preview.

Run with root privileges (raw sockets need them):
    sudo python3 sniffer.py -c 20
    sudo python3 sniffer.py -i eth0 -f "tcp port 80" -c 50 -w capture.pcap
"""

import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw

captured = []  # keep packets so we can optionally save them to a .pcap


def payload_preview(packet, max_bytes=48):
    """Return a short, printable preview of the packet's payload."""
    if not packet.haslayer(Raw):
        return "(no payload)"
    data = bytes(packet[Raw].load)[:max_bytes]
    # Replace non-printable bytes with '.' so the output stays readable
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def handle_packet(packet):
    """Called by scapy once for every captured packet."""
    captured.append(packet)
    time = datetime.now().strftime("%H:%M:%S")

    # Layer 3: who is talking to whom?
    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst
    elif packet.haslayer(ARP):
        print(f"[{time}] ARP  {packet[ARP].psrc} -> {packet[ARP].pdst}  (who-has/is-at)")
        return
    else:
        print(f"[{time}] Other packet: {packet.summary()}")
        return

    # Layer 4: which protocol is carried inside?
    if packet.haslayer(TCP):
        proto = "TCP"
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}  flags={packet[TCP].flags}"
    elif packet.haslayer(UDP):
        proto = "UDP"
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        ports = f"type={packet[ICMP].type} code={packet[ICMP].code}"
    else:
        proto = "OTHER"
        ports = ""

    print(f"[{time}] {proto:<5} {src} -> {dst}  {ports}")
    print(f"           length={len(packet)} bytes | payload: {payload_preview(packet)}")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=20, help="number of packets (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    parser.add_argument("-w", "--write", help="save captured packets to this .pcap file")
    args = parser.parse_args()

    print(f"Sniffing... iface={args.iface or 'default'} filter='{args.filter or 'none'}' (Ctrl+C to stop)\n")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=handle_packet,
              count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied: run with sudo.")
        return

    print(f"\nCaptured {len(captured)} packets.")
    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved to {args.write} (open it in Wireshark).")


if __name__ == "__main__":
    main()

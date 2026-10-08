# CodeAlpha_NetworkSniffer

A basic network sniffer written in Python with [Scapy](https://scapy.net/), built for the CodeAlpha Cyber Security internship (Task 1).

## What it does

- Captures live network packets
- Shows source and destination IP addresses
- Identifies the protocol (TCP, UDP, ICMP, ARP)
- Shows ports, TCP flags, packet length and a payload preview
- Supports BPF filters and optional saving to a `.pcap` file (openable in Wireshark)

## How it works

Every packet is built in layers: Ethernet, then IP (who is talking to whom), then TCP/UDP/ICMP (which protocol and ports), then the payload (the data). Scapy's `sniff()` captures packets and calls `handle_packet()` for each one. That function checks which layers are present and prints their fields.

## Requirements

- Linux (tested on Parrot OS)
- Python 3
- Scapy: `sudo apt install python3-scapy`
- Root privileges (raw sockets require them)

## Usage

```bash
sudo python3 sniffer.py -c 20                          # capture 20 packets
sudo python3 sniffer.py -f "icmp" -c 10                # only ping packets
sudo python3 sniffer.py -f "udp port 53" -c 10         # only DNS
sudo python3 sniffer.py -i eth0 -c 50 -w capture.pcap  # pick interface, save pcap
```

| Option | Meaning |
|---|---|
| `-i` | network interface |
| `-c` | number of packets (0 = unlimited) |
| `-f` | BPF filter |
| `-w` | save packets to a .pcap file |

## Example output

```
[23:38:05] UDP   102.218.49.232 -> 10.29.113.211  443 -> 33976
           length=1292 bytes | payload: Z........9.. X......t.f...
```

This is QUIC (HTTP/3) traffic on UDP port 443. The payload looks random because QUIC is encrypted, so the packet's metadata is visible but its content is not.



## What I learned

- How packets are structured in layers
- How TCP, UDP and ICMP differ
- Why encrypted traffic (HTTPS/QUIC) hides its payload while metadata stays visible
- How to use BPF filters and save captures for Wireshark

## Disclaimer

For educational use only. Only capture traffic on networks you own or have permission to monitor.

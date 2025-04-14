#!/usr/bin/env python3

import argparse
from firewall import MiniFirewall

def main():
    parser = argparse.ArgumentParser(description="Mini Firewall CLI")
    parser.add_argument('--src-ip', required=True, help='Source IP address')
    parser.add_argument('--dest-ip', required=True, help='Destination IP address')
    parser.add_argument('--src-port', type=int, required=True, help='Source port')
    parser.add_argument('--dest-port', type=int, required=True, help='Destination port')
    parser.add_argument('--protocol', required=True, choices=['TCP', 'UDP', 'ICMP'], help='Protocol')

    args = parser.parse_args()

    # Simulate a packet for testing
    from scapy.all import IP, TCP, UDP, ICMP

    ip_layer = IP(src=args.src_ip, dst=args.dest_ip)

    if args.protocol == 'TCP':
        transport_layer = TCP(sport=args.src_port, dport=args.dest_port)
    elif args.protocol == 'UDP':
        transport_layer = UDP(sport=args.src_port, dport=args.dest_port)
    elif args.protocol == 'ICMP':
        transport_layer = ICMP()

    packet = ip_layer / transport_layer

    # Load firewall and test the packet
    fw = MiniFirewall()
    fw.packet_handler(packet)

if __name__ == "__main__":
    main()

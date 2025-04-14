#!/usr/bin/env python3

import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import yaml
import logging
from datetime import datetime

class MiniFirewall:
    def __init__(self, config_file='firewall_rules.yaml'):
        self.rules = self.load_rules(config_file)
        self.setup_logging()
        
    def load_rules(self, config_file):
        """Load firewall rules from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(f"Config file {config_file} not found. Using default rules.")
            return self.get_default_rules()
    
    def get_default_rules(self):
        """Return default firewall rules"""
        return {
            'blocked_ips': [],
            'blocked_ports': [],
            'allowed_protocols': ['TCP', 'UDP', 'ICMP'],
            'logging': True
        }
    
    def setup_logging(self):
        """Configure logging for the firewall"""
        logging.basicConfig(
            filename='firewall.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('MiniFirewall')
    
    def start(self):
        """Start the firewall"""
        print("Starting Mini Firewall...")
        print(f"Loaded rules: {self.rules}")
        try:
            sniff(prn=self.packet_handler, store=0)
        except PermissionError:
            print("Error: Need root/admin privileges to capture packets")
        except KeyboardInterrupt:
            print("\nFirewall stopped by user")
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        if IP in packet:
            self.process_ip_packet(packet)
    
    def process_ip_packet(self, packet):
        """Process IP packets and apply rules"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for blocked IPs
        if self.is_ip_blocked(src_ip) or self.is_ip_blocked(dst_ip):
            self.log_and_block(packet, "Blocked IP")
            return
        
        # Check protocol
        if not self.is_protocol_allowed(packet):
            self.log_and_block(packet, "Blocked protocol")
            return
        
        # Check for blocked ports (TCP/UDP only)
        if (TCP in packet or UDP in packet) and not self.is_port_allowed(packet):
            self.log_and_block(packet, "Blocked port")
            return
        
        # If all checks passed, log allowed packet
        self.log_packet(packet, "Allowed")

    def is_ip_blocked(self, ip):
        """Check if IP is in blocked list"""
        return ip in self.rules.get('blocked_ips', [])

    def is_protocol_allowed(self, packet):
        """Check if packet protocol is allowed"""
        protocol = None
        if TCP in packet:
            protocol = 'TCP'
        elif UDP in packet:
            protocol = 'UDP'
        elif ICMP in packet:
            protocol = 'ICMP'
        
        allowed = self.rules.get('allowed_protocols', [])
        return protocol in allowed if protocol else True

    def is_port_allowed(self, packet):
        """Check if packet port is allowed"""
        blocked_ports = self.rules.get('blocked_ports', [])
        sport, dport = None, None
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        
        # Check if either source or destination port is blocked
        return not (sport in blocked_ports or dport in blocked_ports)

    def log_and_block(self, packet, reason):
        """Log and block a packet"""
        self.log_packet(packet, reason)
        # Send RST for TCP connections to terminate them
        if TCP in packet:
            self.send_rst(packet)

    def send_rst(self, packet):
        """Send TCP RST packet to terminate connection"""
        if IP in packet and TCP in packet:
            ip = packet[IP]
            tcp = packet[TCP]
            
            # Craft RST packet
            rst_pkt = IP(src=ip.dst, dst=ip.src)/ \
                     TCP(sport=tcp.dport, dport=tcp.sport,
                         seq=tcp.ack, ack=tcp.seq + 1,
                         flags="R")
            
            try:
                send(rst_pkt, verbose=0)
            except Exception as e:
                self.logger.error(f"Error sending RST: {e}")

    def log_packet(self, packet, action):
        """Log packet details"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'source_ip': packet[IP].src if IP in packet else None,
            'dest_ip': packet[IP].dst if IP in packet else None,
            'protocol': None,
            'source_port': None,
            'dest_port': None,
            'length': len(packet)
        }
        
        if TCP in packet:
            log_entry['protocol'] = 'TCP'
            log_entry['source_port'] = packet[TCP].sport
            log_entry['dest_port'] = packet[TCP].dport
        elif UDP in packet:
            log_entry['protocol'] = 'UDP'
            log_entry['source_port'] = packet[UDP].sport
            log_entry['dest_port'] = packet[UDP].dport
        elif ICMP in packet:
            log_entry['protocol'] = 'ICMP'
        
        if self.rules.get('logging', True):
            self.logger.info(f"{action}: {log_entry}")
        print(f"{action} packet: {log_entry}")

if __name__ == "__main__":
    firewall = MiniFirewall()
    firewall.start()
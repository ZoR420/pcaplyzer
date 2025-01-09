import dpkt
import socket
import datetime
from openai import OpenAI
import os
from typing import List, Dict
import json
import sys

def mac_addr(address):
    """Convert MAC address to string format."""
    return ':'.join('%02x' % b for b in address)

class PcapParser:
    def __init__(self):
        # Initialize OpenAI client with your API key
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.parsed_packets = []

    def parse_pcap(self, pcap_file: str) -> List[Dict]:
        """Parse PCAP file and store packet information"""
        print(f"Opening PCAP file: {pcap_file}", file=sys.stderr)
        try:
            with open(pcap_file, 'rb') as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                    print("Successfully created PCAP reader", file=sys.stderr)
                except Exception as e:
                    print(f"Failed to create PCAP reader: {e}", file=sys.stderr)
                    # Try pcapng format if pcap fails
                    try:
                        f.seek(0)
                        pcap = dpkt.pcapng.Reader(f)
                        print("Successfully created PCAPNG reader", file=sys.stderr)
                    except Exception as e2:
                        print(f"Failed to create PCAPNG reader: {e2}", file=sys.stderr)
                        raise Exception(f"File is neither PCAP nor PCAPNG format: {e2}")

                packet_count = 0
                for timestamp, buf in pcap:
                    try:
                        packet_count += 1
                        eth = dpkt.ethernet.Ethernet(buf)
                        
                        # Basic packet info
                        packet_info = {
                            'timestamp': datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                            'length': len(buf),
                            'eth_type': hex(eth.type),
                            'src_mac': mac_addr(eth.src),
                            'dst_mac': mac_addr(eth.dst),
                            'protocol_name': 'UNKNOWN'
                        }

                        # Handle different packet types
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            packet_info.update({
                                'protocol_name': 'IP',
                                'ip_version': ip.v,
                                'source_ip': socket.inet_ntoa(ip.src),
                                'dest_ip': socket.inet_ntoa(ip.dst),
                                'protocol': ip.p,
                                'ip_len': ip.len
                            })

                            # Handle TCP/UDP
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp = ip.data
                                packet_info.update({
                                    'protocol_name': 'TCP',
                                    'source_port': tcp.sport,
                                    'dest_port': tcp.dport,
                                    'tcp_flags': {
                                        'FIN': (tcp.flags & dpkt.tcp.TH_FIN) != 0,
                                        'SYN': (tcp.flags & dpkt.tcp.TH_SYN) != 0,
                                        'RST': (tcp.flags & dpkt.tcp.TH_RST) != 0,
                                        'ACK': (tcp.flags & dpkt.tcp.TH_ACK) != 0
                                    }
                                })
                            elif isinstance(ip.data, dpkt.udp.UDP):
                                udp = ip.data
                                packet_info.update({
                                    'protocol_name': 'UDP',
                                    'source_port': udp.sport,
                                    'dest_port': udp.dport
                                })

                        elif isinstance(eth.data, dpkt.arp.ARP):
                            arp = eth.data
                            packet_info.update({
                                'protocol_name': 'ARP',
                                'arp_op': 'REQUEST' if arp.op == dpkt.arp.ARP_OP_REQUEST else 'REPLY',
                                'src_ip': socket.inet_ntoa(arp.spa),
                                'dst_ip': socket.inet_ntoa(arp.tpa),
                                'src_mac': mac_addr(arp.sha),
                                'dst_mac': mac_addr(arp.tha)
                            })

                        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                            packet_info['protocol_name'] = 'IPv6'
                        elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                            packet_info['protocol_name'] = 'ARP'
                        elif eth.type == dpkt.ethernet.ETH_TYPE_REVARP:
                            packet_info['protocol_name'] = 'REVARP'
                        elif eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
                            packet_info['protocol_name'] = 'VLAN'
                        elif eth.type == dpkt.ethernet.ETH_TYPE_CDP:
                            packet_info['protocol_name'] = 'CDP'

                        self.parsed_packets.append(packet_info)
                        
                    except Exception as e:
                        print(f"Error parsing packet {packet_count}: {e}", file=sys.stderr)
                        continue

                print(f"Total packets processed: {packet_count}", file=sys.stderr)
                print(f"Successfully parsed packets: {len(self.parsed_packets)}", file=sys.stderr)

        except FileNotFoundError:
            print(f"PCAP file not found: {pcap_file}", file=sys.stderr)
            raise
        except Exception as e:
            print(f"Error opening PCAP file: {e}", file=sys.stderr)
            raise

        return self.parsed_packets

    def get_analysis_data(self) -> Dict:
        """Get comprehensive analysis data about the PCAP file"""
        if not self.parsed_packets:
            print("No packets were successfully parsed", file=sys.stderr)
            return {
                'packet_count': 0,
                'protocols': [],
                'protocol_counts': {},
                'ip_addresses': {
                    'source': [],
                    'destination': []
                },
                'mac_addresses': {
                    'source': [],
                    'destination': []
                },
                'tcp_ports': [],
                'udp_ports': [],
                'packet_sizes': {
                    'min': 0,
                    'max': 0,
                    'average': 0,
                    'total': 0
                },
                'time_range': {
                    'start': None,
                    'end': None
                },
                'dns_queries': [],
                'error': 'No packets were successfully parsed'
            }

        # Initialize data structure
        data = {
            'packet_count': len(self.parsed_packets),
            'protocols': set(),
            'protocol_counts': {},
            'ip_addresses': {
                'source': set(),
                'destination': set()
            },
            'mac_addresses': {
                'source': set(),
                'destination': set()
            },
            'tcp_ports': set(),
            'udp_ports': set(),
            'packet_sizes': {
                'min': float('inf'),
                'max': 0,
                'total': 0
            },
            'time_range': {
                'start': None,
                'end': None
            },
            'dns_queries': []
        }

        # Process each packet
        for packet in self.parsed_packets:
            # Protocols
            proto = packet.get('protocol_name', 'Unknown')
            data['protocols'].add(proto)
            data['protocol_counts'][proto] = data['protocol_counts'].get(proto, 0) + 1
            
            # MAC addresses
            data['mac_addresses']['source'].add(packet['src_mac'])
            data['mac_addresses']['destination'].add(packet['dst_mac'])
            
            # IP addresses (if present)
            if 'source_ip' in packet:
                data['ip_addresses']['source'].add(packet['source_ip'])
            if 'dest_ip' in packet:
                data['ip_addresses']['destination'].add(packet['dest_ip'])
            
            # Ports (if present)
            if 'source_port' in packet:
                if packet.get('protocol_name') == 'TCP':
                    data['tcp_ports'].add(packet['source_port'])
                    data['tcp_ports'].add(packet['dest_port'])
                elif packet.get('protocol_name') == 'UDP':
                    data['udp_ports'].add(packet['source_port'])
                    data['udp_ports'].add(packet['dest_port'])
            
            # Packet sizes
            length = packet['length']
            data['packet_sizes']['min'] = min(data['packet_sizes']['min'], length)
            data['packet_sizes']['max'] = max(data['packet_sizes']['max'], length)
            data['packet_sizes']['total'] += length

            # Time range
            timestamp = datetime.datetime.strptime(packet['timestamp'], '%Y-%m-%d %H:%M:%S')
            if data['time_range']['start'] is None or timestamp < data['time_range']['start']:
                data['time_range']['start'] = timestamp
            if data['time_range']['end'] is None or timestamp > data['time_range']['end']:
                data['time_range']['end'] = timestamp

        # Convert sets to lists for JSON serialization
        data['protocols'] = list(data['protocols'])
        data['ip_addresses']['source'] = list(data['ip_addresses']['source'])
        data['ip_addresses']['destination'] = list(data['ip_addresses']['destination'])
        data['mac_addresses']['source'] = list(data['mac_addresses']['source'])
        data['mac_addresses']['destination'] = list(data['mac_addresses']['destination'])
        data['tcp_ports'] = list(data['tcp_ports'])
        data['udp_ports'] = list(data['udp_ports'])

        # Calculate average packet size
        data['packet_sizes']['average'] = data['packet_sizes']['total'] / len(self.parsed_packets) if self.parsed_packets else 0

        # Convert timestamps to strings
        if data['time_range']['start']:
            data['time_range']['start'] = data['time_range']['start'].strftime('%Y-%m-%d %H:%M:%S')
        if data['time_range']['end']:
            data['time_range']['end'] = data['time_range']['end'].strftime('%Y-%m-%d %H:%M:%S')

        return data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_parser.py <pcap_file>", file=sys.stderr)
        sys.exit(1)

    pcap_file = sys.argv[1]
    parser = PcapParser()
    
    try:
        print(f"Starting analysis of {pcap_file}", file=sys.stderr)
        parser.parse_pcap(pcap_file)
        analysis_data = parser.get_analysis_data()
        # Output JSON to stdout
        print(json.dumps(analysis_data))
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}", file=sys.stderr)
        # Output empty JSON with error
        print(json.dumps({
            'error': str(e),
            'packet_count': 0,
            'protocols': [],
            'protocol_counts': {},
            'ip_addresses': {'source': [], 'destination': []},
            'mac_addresses': {'source': [], 'destination': []},
            'tcp_ports': [],
            'udp_ports': [],
            'packet_sizes': {'min': 0, 'max': 0, 'average': 0, 'total': 0},
            'time_range': {'start': None, 'end': None},
            'dns_queries': []
        }))
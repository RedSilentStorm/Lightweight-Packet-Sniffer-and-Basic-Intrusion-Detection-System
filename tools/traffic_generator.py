#!/usr/bin/env python3
"""
Simple traffic PCAP generator for testing the IDS.
Run: python3 tools/traffic_generator.py output.pcap --type high-rate
"""
import argparse
import struct
import time

# minimal PCAP writer (pcap global header + simple packets)
PCAP_GLOBAL_HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def write_pcap(filename, packets):
    with open(filename, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack('<IIII', sec, usec, len(pkt), len(pkt)))
            f.write(pkt)

def make_eth_ipv4_udp(src_ip, dst_ip, src_port=40000, dst_port=53, payload=b'data'):
    def ip_to_bytes(ip):
        return bytes(int(x) for x in ip.split('.'))
    eth = b'\xff'*6 + b'\x00'*6 + struct.pack('>H', 0x0800)
    src_bytes = ip_to_bytes(src_ip)
    dst_bytes = ip_to_bytes(dst_ip)
    version_ihl = (4 << 4) | 5
    tos = 0
    total_length = 20 + 8 + len(payload)
    identification = 0
    flags_frag = 0
    ttl = 64
    proto = 17
    checksum = 0
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src_bytes, dst_bytes)
    udp_len = 8 + len(payload)
    udp = struct.pack('!HHHH', src_port, dst_port, udp_len, 0) + payload
    return eth + ip_header + udp

def gen_high_rate():
    """Generate high-rate traffic from two burst sources"""
    packets = []
    t = time.time()
    
    # First burst source: 10 packets
    for i in range(10):
        pkt = make_eth_ipv4_udp('192.168.1.100', '10.0.0.1', 40000+i, 53, b'q')
        packets.append((t + i*0.05, pkt))
    
    # Second burst source: 10 packets
    for i in range(10):
        pkt = make_eth_ipv4_udp('203.0.113.50', '10.0.0.1', 50000+i, 53, b'q')
        packets.append((t + 0.5 + i*0.05, pkt))
    
    return packets

def gen_normal():
    """Generate low-rate normal traffic unlikely to trigger IDS."""
    packets = []
    t = time.time()

    for i in range(8):
        src_octet = 10 + i
        pkt = make_eth_ipv4_udp(f'192.168.1.{src_octet}', '10.0.0.1', 41000 + i, 53, b'q')
        packets.append((t + i * 1.2, pkt))

    return packets

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output')
    parser.add_argument('--type', choices=['normal','high-rate'], default='high-rate')
    args = parser.parse_args()
    if args.type == 'high-rate':
        pkts = gen_high_rate()
    else:
        pkts = gen_normal()
    write_pcap(args.output, pkts)
    print(f'Wrote {len(pkts)} packets to {args.output}')

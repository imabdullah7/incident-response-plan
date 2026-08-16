#!/usr/bin/env python3
"""
analyze_pcap.py

Simple, human-readable script to analyze a pcap/tcpdump capture for DNS activity
and ICMP "Destination unreachable: Port unreachable" messages.

Usage:
    python3 analyze_pcap.py /path/to/capture.pcap

This script uses scapy to read packets and prints a short human-friendly summary.
"""

from collections import Counter
import argparse
import json
import sys

try:
    from scapy.all import rdpcap, UDP, DNS, DNSQR, ICMP, IP
except Exception as e:
    print("Error: scapy is required to run this script. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise


def analyze(pcap_path):
    packets = rdpcap(pcap_path)

    stats = {
        "total_packets": 0,
        "dns_queries": 0,
        "dns_responses": 0,
        "udp_port_53_packets": 0,
        "icmp_port_unreachable_count": 0,
        "icmp_port_unreachable_details": [],
    }

    # Track which hosts and ports were mentioned in ICMP payloads
    icmp_affected = Counter()

    for pkt in packets:
        stats["total_packets"] += 1

        # UDP / DNS activity
        if UDP in pkt:
            udp = pkt[UDP]
            # count any UDP packet that has source or dest port 53
            if udp.sport == 53 or udp.dport == 53:
                stats["udp_port_53_packets"] += 1

            # If DNS layer present, count query/response
            if DNS in pkt:
                dns = pkt[DNS]
                # DNS.qr == 0 -> query, ==1 -> response
                if dns.qr == 0:
                    stats["dns_queries"] += 1
                else:
                    stats["dns_responses"] += 1

        # ICMP Destination Unreachable (type 3), code 3 = port unreachable
        if ICMP in pkt and IP in pkt:
            icmp = pkt[ICMP]
            ip = pkt[IP]
            if icmp.type == 3 and icmp.code == 3:
                stats["icmp_port_unreachable_count"] += 1

                # Try to extract the inner (original) packet's IP/UDP headers from ICMP payload
                # Scapy often nests the original IP as icmp.payload (which may be a Raw or IP)
                inner = None
                try:
                    inner = icmp.payload
                except Exception:
                    inner = None

                detail = {"time": pkt.time, "src": ip.src, "dst": ip.dst}

                # If inner is an IP packet, try to get udp ports
                if inner and hasattr(inner, 'proto') and inner.payload:
                    # inner may be an IP instance
                    if inner.name == 'IP':
                        inner_ip = inner
                        # inner payload might be UDP
                        if hasattr(inner_ip.payload, 'sport') and hasattr(inner_ip.payload, 'dport'):
                            detail.update({
                                "orig_src": inner_ip.src,
                                "orig_dst": inner_ip.dst,
                                "orig_sport": getattr(inner_ip.payload, 'sport', None),
                                "orig_dport": getattr(inner_ip.payload, 'dport', None),
                            })
                            icmp_affected[(inner_ip.dst, getattr(inner_ip.payload, 'dport', None))] += 1
                stats["icmp_port_unreachable_details"].append(detail)

    # Build a short summary
    summary = {
        "total_packets": stats["total_packets"],
        "udp_port_53_packets": stats["udp_port_53_packets"],
        "dns_queries": stats["dns_queries"],
        "dns_responses": stats["dns_responses"],
        "icmp_port_unreachable_count": stats["icmp_port_unreachable_count"],
        "icmp_affected_summary": icmp_affected.most_common(),
    }

    return summary, stats


def main():
    parser = argparse.ArgumentParser(description="Analyze pcap for DNS and ICMP port-unreachable events")
    parser.add_argument("pcap", help="Path to pcap or pcapng file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    summary, stats = analyze(args.pcap)

    if args.json:
        print(json.dumps({"summary": summary}, indent=2))
        return

    # Human-friendly output
    print("PCAP Analysis Report")
    print("====================")
    print(f"Total packets: {summary['total_packets']}")
    print(f"UDP packets involving port 53: {summary['udp_port_53_packets']}")
    print(f"DNS queries: {summary['dns_queries']}")
    print(f"DNS responses: {summary['dns_responses']}")
    print(f"ICMP Destination Unreachable (Port Unreachable) messages: {summary['icmp_port_unreachable_count']}")

    if summary['icmp_port_unreachable_count'] > 0:
        print('\nTop affected destinations and ports (destination_ip, port, count):')
        for (dst_port_tuple, cnt) in summary['icmp_affected_summary']:
            dst, port = dst_port_tuple
            print(f" - {dst}:{port} -> {cnt} time(s)")

    print('\nInterpretation:')
    if summary['icmp_port_unreachable_count'] > 0:
        print(' ICMP port-unreachable messages indicate that UDP packets reached a host that does not have a service listening on the target port (commonly port 53 for DNS).')
    else:
        print(' No ICMP port-unreachable messages were observed in this capture.')


if __name__ == '__main__':
    main()

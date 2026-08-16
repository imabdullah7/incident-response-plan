# Cybersecurity Incident Report

Short description
A concise cybersecurity incident report documenting DNS and ICMP traffic analysis captured with tcpdump.

Purpose of the report
This report documents the investigation of DNS resolution failures observed in network traffic, explains the analysis methodology, and summarizes findings and likely causes. It is suitable for inclusion in a cybersecurity student portfolio.

Technologies / Tools used
- tcpdump
- DNS (Domain Name System)
- ICMP (Internet Control Message Protocol)
- UDP (User Datagram Protocol)

Summary of the incident
DNS requests were sent using UDP, but DNS responses were not received; instead, ICMP "Destination unreachable: Port unreachable" messages were observed. These ICMP errors indicate that UDP port 53 (the standard DNS port) was unreachable from the perspective of the network path or the destination host.

Key finding
The DNS server or DNS service was not responding to UDP port 53; ICMP port-unreachable messages were observed indicating DNS traffic could not be delivered to the service.

Possible cause
- The DNS service on the server was down or stopped.
- A firewall or network configuration is blocking/blackholing UDP port 53.
- A routing or host-level configuration issue prevents UDP traffic reaching the DNS process.

Investigation methodology
1. Captured network traffic with tcpdump during the incident window.
2. Filtered and inspected UDP/DNS traffic and ICMP messages.
3. Correlated timestamps and source/destination IPs to determine which hosts attempted DNS resolution and which host returned ICMP errors.
4. Checked for ICMP "Destination unreachable: Port unreachable" messages indicating the destination port was not available.
5. Used the DNS port (UDP 53) information to focus on firewall/service availability checks.

Link to the full report
See the full incident report: Cybersecurity-Incident-Report.md

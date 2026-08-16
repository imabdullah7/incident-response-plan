Usage — analyze_pcap.py

Overview
This small toolkit helps you inspect a tcpdump/pcap capture for DNS queries and ICMP "Destination unreachable: Port unreachable" messages. It is intended to be easy to read and suitable for teaching or a portfolio.

Prerequisites
- Python 3.8+
- Install dependencies: pip install -r requirements.txt

Quick start
1. Install dependencies:
   pip install -r requirements.txt

2. Run the analysis:
   bin/run-analysis.sh /path/to/capture.pcap

   Or:
   python3 tools/analyze_pcap.py /path/to/capture.pcap

Options
--json   Output summary as JSON for automation.

Example output (human-friendly)
PCAP Analysis Report
====================
Total packets: 1245
UDP packets involving port 53: 25
DNS queries: 20
DNS responses: 0
ICMP Destination Unreachable (Port Unreachable) messages: 7

Interpretation
ICMP port-unreachable messages indicate that a host received UDP packets aimed at a port where no process was listening (commonly port 53 for DNS). A surplus of these messages alongside DNS queries suggests the DNS service may be down or a firewall is blocking UDP/53.

Notes and safety
- Do not upload sensitive captures to public repositories. Remove any packets containing credentials, tokens, or private IPs before publishing.
- If you plan to share captures for debugging, sanitize or redact sensitive fields first.

License / attribution
Add a LICENSE to the repository if you want to set reuse terms; I can add MIT, Apache-2.0, or another license on request.

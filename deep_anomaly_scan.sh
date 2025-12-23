#!/bin/bash

# Script for basic deep packet inspection using tshark
# It expects the path to a pcap file as the first argument.

PCAP_FILE="$1"
OUTPUT_PREFIX=$(basename "$PCAP_FILE" .pcap)

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file '$PCAP_FILE' not found."
    exit 1
fi

echo "--- Deep Anomaly Scan Report for $PCAP_FILE ---"
echo "Timestamp: $(date)"
echo ""

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Please install it (e.g., sudo apt-get install tshark)."
    exit 1
fi

echo "--- Protocol Hierarchy Statistics ---"
tshark -r "$PCAP_FILE" -q -z io,phs
echo ""

echo "--- IP Conversations ---"
tshark -r "$PCAP_FILE" -q -z conv,ip | head -n 15 # Show top conversations
echo ""

echo "--- TCP Conversations ---"
tshark -r "$PCAP_FILE" -q -z conv,tcp | head -n 15
echo ""

echo "--- UDP Conversations ---"
tshark -r "$PCAP_FILE" -q -z conv,udp | head -n 15
echo ""

echo "--- DNS Queries (showing query name, type, and response if available) ---"
tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0" -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -E header=y -E separator=, 2>/dev/null | head -n 20
echo ""

echo "--- HTTP GET/POST Requests (showing Host and URI) ---"
tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e frame.number -e ip.src -e http.request.method -e http.host -e http.request.uri -E header=y -E separator=, 2>/dev/null | head -n 20
echo ""

echo "--- Packets with unusual TCP Flags (e.g., SYN-FIN, SYN-RST) ---"
# Christmas Tree (FIN, URG, PSH)
tshark -r "$PCAP_FILE" -Y "tcp.flags == 0x029" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags.str -E header=y -E separator=, 2>/dev/null
# SYN-FIN
tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1 && tcp.flags.fin == 1" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags.str -E header=y -E separator=, 2>/dev/null
# NULL Flags
tshark -r "$PCAP_FILE" -Y "tcp.flags == 0x000" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags.str -E header=y -E separator=, 2>/dev/null
echo ""

echo "--- Potential Cleartext FTP Credentials ---"
tshark -r "$PCAP_FILE" -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e frame.number -e ip.src -e ftp.request.command -e ftp.request.arg -E header=y -E separator=, 2>/dev/null
echo ""

# Add more tshark commands or other tools (strings, grep, etc.) as needed
# Example: Look for executable file downloads over HTTP
# echo "--- Potential .exe downloads over HTTP ---"
# tshark -r "$PCAP_FILE" -Y "http.request.uri contains \".exe\" || http.response.application_octet_stream" -Tfields -e ip.src -e ip.dst -e http.host -e http.request.uri 2>/dev/null | head
# echo ""

echo "--- End of Deep Anomaly Scan Report ---"
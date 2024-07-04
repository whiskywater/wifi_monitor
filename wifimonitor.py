from scapy.all import sniff, IP, TCP
import logging
from collections import defaultdict
import time

# Set up logging to file
logging.basicConfig(filename='logTraffic.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# A set to keep track of seen IP addresses
seen_ips = set()

# ANSI escape codes for coloring the output
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Threshold for detecting port scan
PORT_SCAN_THRESHOLD = 20
SCAN_TIME_WINDOW = 60  # seconds

# Dictionary to track unique destination ports for each source IP
ip_port_tracker = defaultdict(set)
ip_time_tracker = defaultdict(float)


# Define a function to process each packet
def packet_callback(packet):
    current_time = time.time()
    flagged_ip = None

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        new_ip_message = ""

        if ip_src not in seen_ips:
            new_ip_message += f"{RED}new ip:{RESET} "
            seen_ips.add(ip_src)
        if ip_dst not in seen_ips:
            new_ip_message += f"{RED}new ip:{RESET} "
            seen_ips.add(ip_dst)

        if packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            log_message = f"{new_ip_message}IP src: {ip_src} -> IP dst: {ip_dst} | TCP src port: {tcp_src_port} -> TCP dst port: {tcp_dst_port}"

            # Track unique destination ports for source IP
            ip_port_tracker[ip_src].add(tcp_dst_port)
            ip_time_tracker[ip_src] = current_time

            # Check if the source IP has scanned more than the threshold number of ports
            if len(ip_port_tracker[ip_src]) > PORT_SCAN_THRESHOLD:
                flagged_ip = ip_src
                log_message = f"\n{YELLOW}WARNING: Potential port scan detected from IP:{RESET} {ip_src}\n"

        else:
            log_message = f"{new_ip_message}IP src: {ip_src} -> IP dst: {ip_dst} | Protocol: {protocol}"
    else:
        log_message = packet.summary()

    print(log_message)
    logging.info(log_message)

    # Clean up old entries to prevent memory bloat
    for ip in list(ip_time_tracker.keys()):
        if current_time - ip_time_tracker[ip] > SCAN_TIME_WINDOW:
            del ip_time_tracker[ip]
            del ip_port_tracker[ip]


# Start sniffing without a filter to capture all packets
print("Starting packet sniffing...")
sniff(prn=packet_callback, count=0)  # count=0 means it will continue until interrupted

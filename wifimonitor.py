from scapy.all import sniff, IP, TCP, Raw
import logging
import re

# Set up logging to file
logging.basicConfig(filename='logTraffic.txt', level=logging.INFO, format='%(asctime)s - %(message)s')


# Function to extract HTTP data
def extract_http_info(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        http_info = None

        if payload.startswith('GET') or payload.startswith('POST'):
            headers = payload.split('\r\n')
            request_line = headers[0]
            method, path, version = request_line.split()
            host = ''
            for header in headers:
                if header.startswith('Host:'):
                    host = header.split(': ')[1]
                    break
            http_info = f"{method} {host}{path} {version}"
        return http_info


# Define a function to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            http_info = extract_http_info(packet)
            if http_info:
                log_message = f"HTTP {http_info} | IP src: {ip_src} -> IP dst: {ip_dst}"
                print(log_message)
                logging.info(log_message)
        else:
            log_message = packet.summary()
            print(log_message)
            logging.info(log_message)


# Start sniffing with a filter for HTTP traffic
print("Starting packet sniffing...")
sniff(prn=packet_callback, filter="tcp port 80", count=0)

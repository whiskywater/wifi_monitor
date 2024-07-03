from scapy.all import sniff, IP, TCP, Raw, conf
import logging

# Set up logging to file
logging.basicConfig(filename='logTraffic.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to extract HTTP data
def extract_http_info(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if payload.startswith('GET') or payload.startswith('POST'):
                headers = payload.split('\r\n')
                request_line = headers[0]
                method, path, version = request_line.split()
                host = ''
                for header in headers:
                    if header.startswith('Host:'):
                        host = header.split(': ')[1]
                        break
                return f"{method} {host}{path} {version}"
    except Exception as e:
        logging.error(f"Error extracting HTTP info: {e}")
    return None

# Define a function to process each packet
def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                http_info = extract_http_info(packet)
                if http_info:
                    log_message = f"HTTP {http_info} | IP src: {ip_src} -> IP dst: {ip_dst}"
                else:
                    log_message = f"IP src: {ip_src} -> IP dst: {ip_dst} | No HTTP info"
                print(log_message)
                logging.info(log_message)
            else:
                log_message = packet.summary()
                print(log_message)
                logging.info(log_message)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# List available network interfaces
interfaces = conf.ifaces
print("Available network interfaces:")
for iface in interfaces:
    print(f" - {iface}")

# Specify the network interface (replace with your interface)
interface = input("Enter the network interface to use: ")

# Start sniffing with a filter for HTTP traffic
print(f"Starting packet sniffing on interface {interface}...")
try:
    sniff(prn=packet_callback, filter="tcp port 80", iface=interface, count=0)
except Exception as e:
    logging.error(f"Error starting sniffing: {e}")
    print(f"Error: {e}")

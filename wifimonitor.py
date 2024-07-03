from scapy.all import sniff, IP, TCP
import logging

# Set up logging to file
logging.basicConfig(filename='logTraffic.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Define a function to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            log_message = f"IP src: {ip_src} -> IP dst: {ip_dst} | TCP src port: {tcp_src_port} -> TCP dst port: {tcp_dst_port}"
        else:
            log_message = f"IP src: {ip_src} -> IP dst: {ip_dst} | Protocol: {protocol}"
    else:
        log_message = packet.summary()
    
    print(log_message)
    logging.info(log_message)

# Start sniffing without a filter to capture all packets
print("Starting packet sniffing...")
sniff(prn=packet_callback, count=0)  # count=0 means it will continue until interrupted

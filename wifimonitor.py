from scapy.all import sniff

# Define a function to process each packet
def packet_callback(packet):
    print(packet.summary())

# Start sniffing
print("Starting packet sniffing...")
sniff(prn=packet_callback, count=0)  # count=0 means it will continue until interrupted

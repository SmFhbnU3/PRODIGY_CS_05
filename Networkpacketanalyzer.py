from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process packets
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Convert protocol number to name
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = str(protocol)
        
        print(f"[+] Packet: {proto_name}")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        
        # If it's a TCP/UDP packet, print the payload data
        if TCP in packet or UDP in packet:
            if Raw in packet:
                payload = packet[Raw].load
                print(f"    Payload: {payload}")
        print("-" * 60)

# Main function to start sniffing
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    # Replace 'None' with your network interface, e.g., 'Ethernet' or 'Wi-Fi'
    start_sniffing(interface=None)

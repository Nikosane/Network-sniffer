from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    """
    Processes and prints details of each captured packet.
    """
    print("\n=== New Packet Captured ===")
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    # Check if the packet has a TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("TCP Packet:")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print(f"  Flags: {tcp_layer.flags}")
        print(f"  Sequence Number: {tcp_layer.seq}")
        print(f"  Acknowledgment Number: {tcp_layer.ack}")

    # Check if the packet has a UDP layer
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("UDP Packet:")
        print(f"  Source Port: {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")

    # Check if the packet has an ICMP layer
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print("ICMP Packet:")
        print(f"  Type: {icmp_layer.type}")
        print(f"  Code: {icmp_layer.code}")

    # Show raw payload data if present
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        print("Raw Data:", raw_data)
        
def capture_all_traffic(interface="enp1s0"):
    """
    Captures all network traffic on the specified interface.

    Parameters:
        interface (str): The network interface to capture on (e.g., 'enp1s0' or 'eth0').
    """
    print(f"Starting packet capture on interface: {interface}")
    # Start sniffing on the specified interface
    sniff(iface=interface, prn=packet_callback, store=False)

# Example usage
capture_all_traffic(interface="enp1s0")

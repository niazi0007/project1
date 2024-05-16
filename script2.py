from scapy.all import sniff, Ether, IP

def packet_handler(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Source MAC: {src_mac} --> Destination MAC: {dst_mac}")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip} | Protocol: {protocol}")

# Sniffing packets on the default interface (you might need to adjust this)
sniff(prn=packet_handler, count=10)

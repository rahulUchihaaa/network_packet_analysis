from scapy.all import sniff, IP, TCP, UDP, ICMP , Raw

def packet_callback(packet):
    print("=" * 50)
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] Source IP: {ip_layer.src}")
        print(f"[+] Destination IP: {ip_layer.dst}")
        print(f"[+] Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("[+] TCP Packet")
            print(f"    Source Port: {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("[+] UDP Packet")
            print(f"    Source Port: {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("[+] ICMP Packet")
    
        if packet.haslayer(Raw):
            print(f"[+] Payload:\n{packet[Raw].load.decode(errors='ignore')}")
    else:
        print("[-] Non-IP Packet")

# Capture packets (you may need sudo on Linux/macOS)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)

from scapy.all import sniff


def start_sniffing(interface, block_callback):
    print(f"Initializing sniffer on interface: {interface}")

    def packet_callback(packet):
        print("Packet received!")  # Debug: confirm packets are captured
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            print(f"IP Source: {ip_src}")
            block_callback(ip_src)

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error in sniffer: {e}")

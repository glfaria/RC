from scapy.all import ARP, ICMP, TCP, UDP, IP, Ether
from datetime import datetime

def classify_packet(pkt):
    data = {}

    data["timestamp"] = datetime.fromtimestamp(pkt.time).isoformat()
    data["length"] = len(pkt)

    if pkt.haslayer(Ether):
        data["mac_src"] = pkt[Ether].src
        data["mac_dst"] = pkt[Ether].dst

    if pkt.haslayer(IP):
        data["ip_src"] = pkt[IP].src
        data["ip_dst"] = pkt[IP].dst

    if pkt.haslayer(ARP):
        data["protocol"] = "ARP"
        data["summary"] = "ARP request" if pkt[ARP].op == 1 else "ARP reply"

    elif pkt.haslayer(ICMP):
        data["protocol"] = "ICMP"
        data["summary"] = "ICMP packet"

    elif pkt.haslayer(TCP):
        data["protocol"] = "TCP"
        data["summary"] = "TCP segment"

    elif pkt.haslayer(UDP):
        data["protocol"] = "UDP"
        data["summary"] = "UDP datagram"

    elif pkt.haslayer(IP):
        data["protocol"] = "IPv4"
        data["summary"] = pkt.summary()

    else:
        data["protocol"] = "OTHER"
        data["summary"] = pkt.summary()

    return data
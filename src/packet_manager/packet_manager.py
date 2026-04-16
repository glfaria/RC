from packet import Packet
from classifier import classify_packet
from io import write_packet

class PacketManager:
    def __init__(self):
        self.packets = []

    def handle_packet(self, pkt):
        data = classify_packet(pkt)
        if not data: return
        packet = Packet(
            timestamp=data["timestamp"],
            protocol=data["protocol"],
            src=data.get("src"),
            dst=data.get("dst"),
            length=data["length"],
            summary=data["summary"]
        )
        self.store(packet)
        write_packet(packet)

    def store(self, packet):
        self.packets.append(packet)

    def get_all(self):
        return self.packets

    def filter_by_protocol(self, protocol):
        return [p for p in self.packets if p.protocol == protocol]

    def filter_by_ip(self, ip):
        return [
            p for p in self.packets
            if p.src == ip or p.dst == ip
        ]

    def filter_by_mac(self, mac):
        return [
            p for p in self.packets
            if p.src == mac or p.dst == mac
        ]
    
    def get_by_time_range(self, start, end):
        return [
            p for p in self.packets
            if start <= p.timestamp <= end
        ]

    def count_by_protocol(self):
        counts = {}
        for p in self.packets:
            counts[p.protocol] = counts.get(p.protocol, 0) + 1
        return counts
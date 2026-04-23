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

    def filter_packets(self, protocol=None, ip=None, mac=None, start=None, end=None):
        result = self.packets

        if protocol:
            result = [p for p in result if p.protocol == protocol]

        if ip:
            result = [p for p in result if p.src == ip or p.dst == ip]

        if mac:
            result = [p for p in result if p.src == mac or p.dst == mac]

        if start is not None:
            result = [p for p in result if p.timestamp >= start]

        if end is not None:
            result = [p for p in result if p.timestamp <= end]

        return result

    def count_by_protocol(self):
        counts = {}
        for p in self.packets:
            counts[p.protocol] = counts.get(p.protocol, 0) + 1
        return counts
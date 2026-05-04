from .packet import Packet
from .classifier import classify_packet
from .filters import PacketFilter

class PacketManager:
    def __init__(self, output):
        self.packets = []
        self.output = output
        self.filter = PacketFilter()

    def handle_packet(self, pkt):
        raw = bytes(pkt)
        data = classify_packet(raw)
        if not data:
            return

        packet = Packet(
            timestamp=data["timestamp"],
            protocol=data["protocol"],
            src=data.get("ip_src") or data.get("mac_src"),
            dst=data.get("ip_dst") or data.get("mac_dst"),
            length=data["length"],
            summary=data["summary"],
            raw=raw,
            details=data["details"],
        )

        self.store(packet)

        if self.filter.apply(packet):
            self.output.write_packet(packet)

    def store(self, packet):
        self.packets.append(packet)

    def get_filtered_packets(self):
        return self.filter.filter_list(self.packets)

    def set_filters(self, **kwargs):
        self.filter.set(**kwargs)

    def count_by_protocol(self, packets=None):
        packets = packets or self.packets
        counts = {}
        for p in packets:
            counts[p.protocol] = counts.get(p.protocol, 0) + 1
        return counts

    def get_all(self):
        return self.packets
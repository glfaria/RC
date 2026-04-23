from .packet import Packet
from .classifier.classifier import classify_packet
from .filters import PacketFilter

class PacketManager:
    def __init__(self, output):
        self.packets = []
        self.output = output
        self.filter = PacketFilter()

    def handle_packet(self, pkt):
        data = classify_packet(pkt)
        if not data:
            return

        packet = Packet(
            timestamp=data["timestamp"],
            protocol=data["protocol"],
            src=data.get("src"),
            dst=data.get("dst"),
            length=data["length"],
            summary=data["summary"]
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
class LiveOutput:
    def write_packet(self, packet):
        print(
            f"{packet.timestamp:8} | "
            f"{packet.protocol:5} | "
            f"{packet.src:20} -> {packet.dst:20} | "
            f"{packet.length:4} | "
            f"{packet.summary}"
        )
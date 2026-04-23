class LiveOutput:
    def write_packet(self, packet):
        print(packet.to_dict())
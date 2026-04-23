class LogOutput:
    def __init__(self, filename):
        self.file = open(filename, "a")

    def write_packet(self, packet):
        self.file.write(str(packet.to_dict()) + "\n")

    def close(self):
        self.file.close()
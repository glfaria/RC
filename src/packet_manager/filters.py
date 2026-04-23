class PacketFilter:
    def __init__(self):
        self.protocol = None
        self.ip = None
        self.mac = None
        self.start = None
        self.end = None

    def set(self, protocol=None, ip=None, mac=None, start=None, end=None):
        self.protocol = protocol
        self.ip = ip
        self.mac = mac
        self.start = start
        self.end = end

    def apply(self, packet):
        if self.protocol and packet.protocol != self.protocol:
            return False

        if self.ip and not (packet.src == self.ip or packet.dst == self.ip):
            return False

        if self.mac and not (packet.src == self.mac or packet.dst == self.mac):
            return False

        if self.start and packet.timestamp < self.start:
            return False

        if self.end and packet.timestamp > self.end:
            return False

        return True

    def filter_list(self, packets):
        return [p for p in packets if self.apply(p)]
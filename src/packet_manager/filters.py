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
        if self.protocol and (packet.protocol or "").casefold() != self.protocol.casefold():
            return False

        if self.ip and not (
            (packet.src or "").casefold() == self.ip.casefold() or 
            (packet.dst or "").casefold() == self.ip.casefold()
        ):
            return False

        if self.mac and not (
            (packet.details["ethernet"]["src_mac"]  or "").casefold() == self.mac.casefold() or 
            (packet.details["ethernet"]["dst_mac"] or "").casefold() == self.mac.casefold()
        ):
            return False

        if self.start and packet.timestamp < self.start:
            return False

        if self.end and packet.timestamp > self.end:
            return False

        return True

    def filter_list(self, packets):
        return [p for p in packets if self.apply(p)]
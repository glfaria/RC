class Packet:
    def __init__(self, timestamp, protocol, src, dst, length, summary):
        self.timestamp = timestamp
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.summary = summary

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src": self.src,
            "dst": self.dst,
            "length": self.length,
            "summary": self.summary,
        }
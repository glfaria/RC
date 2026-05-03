class Packet:
    def __init__(self, timestamp, protocol, src, dst, length, summary, raw=None, details=None):
        self.timestamp = timestamp
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.summary = summary
        self.raw = raw
        self.details = details or {}

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src": self.src,
            "dst": self.dst,
            "length": self.length,
            "summary": self.summary,
            "details": self.details,
        }

    def to_table_dict(self):
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src": self.src,
            "dst": self.dst,
            "length": self.length,
            "summary": self.summary,
        }
from .live import LiveOutput
from .logger import LogOutput

class BothOutput:
    def __init__(self, filename):
        self.live = LiveOutput()
        self.log = LogOutput(filename)

    def write_packet(self, packet):
        self.live.write_packet(packet)
        self.log.write_packet(packet)

    # def close(self):
    #     self.log.close()
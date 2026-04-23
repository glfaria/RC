import json
import os

class LogOutput:
    def __init__(self, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        self.filename = filename
        self.packets = []

    def write_packet(self, packet):
        self.packets.append(packet.to_dict())
        self._save()

    def _save(self):
        with open(self.filename, "w") as f:
            json.dump(self.packets, f, indent=4)

    def close(self):
        self._save()
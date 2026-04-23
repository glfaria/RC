from scapy.all import sniff
import threading

class Capturer:
    def __init__(self, iface=None):
        self.iface = iface
        self.running = False
        self.thread = None

    def start(self, process_packet):
        self.running = True

        def _sniff():
            sniff(
                iface=self.iface,
                prn=process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )

        self.thread = threading.Thread(target=_sniff)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
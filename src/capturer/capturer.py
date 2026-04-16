from scapy.all import sniff

class Capturer:

    def __init__(self, iface=None):
        self.iface = iface
        
    def sniff_packet(self, process_packet):
        sniff(iface=self.iface, prn=process_packet, store=False)
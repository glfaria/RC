from scapy.all import sniff
import threading

class Capturer:
    def __init__(self, iface=None):
        self.iface = iface
        self.running = False
        self.thread = None

    def start(self, handle_packet):
        self.running = True

        def _sniff():
            try:
                sniff(
                    iface=self.iface,
                    prn=handle_packet,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except PermissionError as e:
                print("[ERRO] Permissões insuficientes para capturar pacotes.")
                print("Sugestão: correr com sudo.")
                self.running = False
            except Exception as e:
                print(f"[ERRO inesperado] {e}")
                self.running = False

        self.thread = threading.Thread(target=_sniff)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
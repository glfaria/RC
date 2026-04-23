import argparse
from output.live import LiveOutput
from output.logger import LogOutput
from output.both import BothOutput
from capturer.capturer import Capturer
from packet_manager.packet_manager import PacketManager
from scapy.all import get_if_list

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--mode", choices=["live", "log", "both"], default="live")
    parser.add_argument("--logfile", default="logs/sniffer.json")
    args = parser.parse_args()

    if args.interface not in get_if_list():
        print("Interface inválida")
        return

    if args.mode == "live":
        output = LiveOutput()
    elif args.mode == "log":
        output = LogOutput(args.logfile)
    else:
        output = BothOutput(args.logfile)

    is_running = False

    capturer = Capturer(args.interface)
    manager = PacketManager(output)

    print("\nSniffer pronto.")
    print("Comandos: start | stop | filter | stats | show | exit")

    while True:
        cmd = input("> ").strip().lower()

        if cmd == "start":
            if not is_running:
                capturer.start(manager.handle_packet)
                is_running = True
                print("Captura iniciada")
            else:
                print("Captura já está a correr")

        elif cmd == "stop":
            if is_running:
                capturer.stop()
                is_running = False
                print("Captura parada")
            else:
                print("Captura já está parada")

        elif cmd == "filter":
            manager.set_filters(
                protocol=input("Protocol: ") or None,
                ip=input("IP: ") or None,
                mac=input("MAC: ") or None
            )
            print("Filtros atualizados")

        elif cmd == "show":
            packets = manager.get_filtered_packets()
            for p in packets:
                print(p.to_dict())

        elif cmd == "stats":
            packets = manager.get_filtered_packets()
            print(manager.count_by_protocol(packets))

        elif cmd == "exit":
            capturer.stop()
            break

if __name__ == "__main__":
    main()
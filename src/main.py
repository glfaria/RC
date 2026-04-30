import argparse
from scapy.all import get_if_list
from capturer.capturer import Capturer
from packet_manager.packet_manager import PacketManager
from output.live import LiveOutput
from output.logger import LogOutput
from output.both import BothOutput
from output.tui import run_tui
from output.gui import run_gui


def build_output(mode, logfile):
    if mode == "live":
        return LiveOutput()
    elif mode == "log":
        return LogOutput(logfile)
    elif mode == "both":
        return BothOutput(logfile)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)

    parser.add_argument("--mode", choices=["live", "log", "both"], required=True)
    parser.add_argument("--ui", choices=["tui", "gui"], required=True)

    parser.add_argument("--logfile", default="logs/sniffer.json")

    args = parser.parse_args()

    if args.interface not in get_if_list():
        print("Interface inválida")
        return

    output = build_output(args.mode, args.logfile)

    manager = PacketManager(output)
    capturer = Capturer(args.interface)

    if args.ui == "tui":
        run_tui(manager, capturer)

    elif args.ui == "gui":
        run_gui(manager, capturer)


if __name__ == "__main__":
    main()
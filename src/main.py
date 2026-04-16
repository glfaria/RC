import argparse
from io import LiveOutput, LogOutput, BothOutput

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--mode", choices=["live", "log", "both"], default="live")
    parser.add_argument("--logfile", default="logs/sniffer.json")
    args = parser.parse_args()

    if args.mode == "live":
        output = LiveOutput()
    elif args.mode == "log":
        output = LogOutput(args.logfile)
    elif args.mode == "both":
        output = BothOutput(args.logfile)


if __name__ == "__main__":
    main()


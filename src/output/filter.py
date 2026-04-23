from packet_manager.packet_manager import filter_packets

def get_user_filter():

    print("=== Filters ===")
    print("Press ENTER to skip a filter")

    protocol = input("Protocol: ")
    ip = input("IP: ")
    mac = input("MAC: ")

    print("\n=== Time Interval ===")
    start = input("Start time (HH:MM:SS): ")
    end = input("End time (HH:MM:SS): ")

    protocol = protocol if protocol else None
    ip = ip if ip else None
    mac = mac if mac else None
    start = start if start else None
    end = end if end else None

    filter_packets(protocol=protocol, ip=ip, mac=mac, start=start, end=end)

   


def print_selected_filters(filters):

    print("\n===== Selected Filters =====")

    protocol = filters["protocol"] if filters["protocol"] else "any"
    ip = filters["ip"] if filters["ip"] else "any"
    mac = filters["mac"] if filters["mac"] else "any"

    if filters["start"] and filters["end"]:
        time_interval = f"{filters['start']} - {filters['end']}"
    else:
        time_interval = "none"

    print(f"Protocol: {protocol}")
    print(f"IP: {ip}")
    print(f"MAC: {mac}")
    print(f"Time interval: {time_interval}")

    print("============================\n")
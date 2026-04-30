def run_tui(manager, capturer):
    is_running = False

    print("\nSniffer pronto (TUI mode).")
    print("Comandos: start | stop | filter | stats | show | exit")

    while True:
        cmd = input("> ").strip().lower()

        if cmd == "start":
            if not is_running:
                capturer.start(manager.handle_packet)
                is_running = True
                print("Captura iniciada")
            else:
                print("Já está a correr")

        elif cmd == "stop":
            if is_running:
                capturer.stop()
                is_running = False
                print("Captura parada")
            else:
                print("Já está parada")

        elif cmd == "filter":
            manager.set_filters(
                protocol=input("Protocol: ") or None,
                ip=input("IP: ") or None,
                mac=input("MAC: ") or None
            )
            print("Filtros atualizados")

        elif cmd == "show":
            for p in manager.get_filtered_packets():
                print(p.to_dict())

        elif cmd == "stats":
            print(manager.count_by_protocol(manager.get_filtered_packets()))

        elif cmd == "exit":
            capturer.stop()
            break
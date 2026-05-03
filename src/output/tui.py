def run_tui(manager, capturer):
    is_running = False

    print("\nSniffer pronto (TUI mode).")
    print("Comandos: start | stop | list | view <id> | filter | stats | clear | help | exit")

    def print_table(packets):
        print("\nID  | TIME                | PROTO | SOURCE               -> DESTINATION          | LEN  | INFO")
        print("-" * 90)

        for i, p in enumerate(packets):
            print(
                f"{i:3} | "
                f"{p.timestamp:8} | "
                f"{p.protocol:5} | "
                f"{p.src:20} -> {p.dst:20} | "
                f"{p.length:4} | "
                f"{p.summary}"
            )

    def print_details(packet):
        print("\n" + "=" * 50)
        print(f"Packet Detail")
        print("=" * 50)

        print(f"Timestamp : {packet.timestamp}")
        print(f"Protocol  : {packet.protocol}")
        print(f"Source    : {packet.src}")
        print(f"Dest      : {packet.dst}")
        print(f"Length    : {packet.length}")
        print(f"Summary   : {packet.summary}")

        for layer, fields in packet.details.items():
            print(f"\n--- {layer.upper()} ---")
            for k, v in fields.items():
                print(f"{k:20}: {v}")

        print("=" * 50)

    while True:
        try:
            cmd = input("\n> ").strip().lower()

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

            elif cmd == "list":
                packets = manager.get_filtered_packets()
                if not packets:
                    print("Sem pacotes.")
                else:
                    print_table(packets)

            elif cmd.startswith("view"):
                parts = cmd.split()
                if len(parts) != 2 or not parts[1].isdigit():
                    print("Uso: view <id>")
                    continue

                idx = int(parts[1])
                packets = manager.get_filtered_packets()

                if idx < 0 or idx >= len(packets):
                    print("ID inválido")
                else:
                    print_details(packets[idx])

            elif cmd == "filter":
                manager.set_filters(
                    protocol=input("Protocol: ") or None,
                    ip=input("IP: ") or None,
                    mac=input("MAC: ") or None
                )
                print("Filtros atualizados")

            elif cmd == "stats":
                stats = manager.count_by_protocol(manager.get_filtered_packets())
                print("\nProtocol Stats:")
                for proto, count in stats.items():
                    print(f"{proto:5}: {count}")

            elif cmd == "clear":
                manager.packets.clear()
                print("Pacotes limpos")

            elif cmd == "help":
                print("Comandos: start | stop | list | view <id> | filter | stats | clear | help | exit")

            elif cmd == "exit":
                capturer.stop()
                print("A sair...")
                break

            else:
                print("Comando inválido")

        except KeyboardInterrupt:
            capturer.stop()
            print("\nInterrompido.")
            break
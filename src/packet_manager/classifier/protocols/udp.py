import struct

SERVICES = {
    53: "DNS", 67: "DHCP-server", 68: "DHCP-client", 69: "TFTP",
    123: "NTP", 161: "SNMP", 162: "SNMP-trap", 443: "QUIC",
    500: "IKE", 514: "Syslog", 1900: "SSDP", 5353: "mDNS",
}


def parse_udp(raw: bytes, offset: int, result: dict) -> dict:
    if len(raw) < offset + 8:
        result["protocol"] = "UDP"
        result["summary"] = "UDP datagrama demasiado curto"
        return result

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[offset:offset + 8])
    service = SERVICES.get(dst_port) or SERVICES.get(src_port) or ""

    result["protocol"] = "UDP"
    result["summary"]  = (
        f"UDP {src_port} → {dst_port}"
        + (f" ({service})" if service else "")
        + f" len={length - 8}"
    )
    result["details"]["udp"] = {
        "src_port":    src_port,
        "dst_port":    dst_port,
        "service":     service,
        "length":      length,
        "payload_len": length - 8,
        "checksum":    f"0x{checksum:04x}",
    }
    return result
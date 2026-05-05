import struct

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

FLAG_BITS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def parse_tcp(raw: bytes, offset: int, result: dict) -> dict:
    if len(raw) < offset + 20:
        result["protocol"] = "TCP"
        result["summary"] = "TCP segmento demasiado curto"
        return result

    src_port, dst_port = struct.unpack("!HH", raw[offset:offset + 4])
    seq      = struct.unpack("!I", raw[offset + 4:offset + 8])[0]
    ack      = struct.unpack("!I", raw[offset + 8:offset + 12])[0]
    hdr_len  = (raw[offset + 12] >> 4) * 4
    flags_b  = raw[offset + 13]
    window   = struct.unpack("!H", raw[offset + 14:offset + 16])[0]
    checksum = struct.unpack("!H", raw[offset + 16:offset + 18])[0]
    urgent   = struct.unpack("!H", raw[offset + 18:offset + 20])[0]

    flags       = {name: bool(flags_b & bit) for bit, name in FLAG_BITS}
    active      = [name for bit, name in FLAG_BITS if flags_b & bit]
    service     = SERVICES.get(dst_port) or SERVICES.get(src_port) or ""
    flags_str   = " ".join(active) if active else "—"

    result["protocol"] = "TCP"
    result["summary"]  = (
        f"TCP {src_port} → {dst_port}"
        + (f" [{flags_str}]" if active else "")
        + (f" ({service})" if service else "")
    )
    result["details"]["tcp"] = {
        "src_port":       src_port,
        "dst_port":       dst_port,
        "service":        service,
        "sequence":       seq,
        "acknowledgment": ack,
        "header_length":  hdr_len,
        "flags":          flags,
        "active_flags":   active,
        "window":         window,
        "checksum":       f"0x{checksum:04x}",
        "urgent_pointer": urgent,
    }
    return result
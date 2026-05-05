import struct


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)

def verify_checksum(data: bytes) -> bool:
    """Checksum de internet RFC 1071. Retorna True se válido."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += struct.unpack("!H", data[i:i + 2])[0]
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF
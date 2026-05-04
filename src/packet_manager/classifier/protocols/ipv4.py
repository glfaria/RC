import struct
import ipaddress
from ..utils import verify_checksum
from .tcp  import parse_tcp
from .udp  import parse_udp
from .icmp import parse_icmp

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}

_TRANSPORT: dict[int, callable] = {
    1:  parse_icmp,
    6:  parse_tcp,
    17: parse_udp,
}


def parse_ipv4(raw: bytes, offset: int, result: dict) -> dict:
    if len(raw) < offset + 20:
        result["protocol"] = "IPv4"
        result["summary"]  = "IPv4 frame demasiado curto"
        return result

    ver_ihl = raw[offset]
    version = ver_ihl >> 4
    ihl     = (ver_ihl & 0x0F) * 4

    if version != 4:
        result["summary"] = f"Versão IP inesperada: {version}"
        return result

    tos          = raw[offset + 1]
    total_length = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
    identification = struct.unpack("!H", raw[offset + 4:offset + 6])[0]
    flags_frag   = struct.unpack("!H", raw[offset + 6:offset + 8])[0]
    ttl          = raw[offset + 8]
    proto        = raw[offset + 9]
    checksum     = struct.unpack("!H", raw[offset + 10:offset + 12])[0]
    ip_src       = str(ipaddress.IPv4Address(raw[offset + 12:offset + 16]))
    ip_dst       = str(ipaddress.IPv4Address(raw[offset + 16:offset + 20]))

    result["ip_src"] = ip_src
    result["ip_dst"] = ip_dst
    result["details"]["ipv4"] = {
        "version":        version,
        "ihl":            ihl,
        "tos":            tos,
        "total_length":   total_length,
        "identification": f"0x{identification:04x}",
        "flags": {
            "DF": bool((flags_frag >> 14) & 1),
            "MF": bool((flags_frag >> 13) & 1),
        },
        "fragment_offset": (flags_frag & 0x1FFF) * 8,
        "ttl":             ttl,
        "protocol":        proto,
        "protocol_name":   PROTO_NAMES.get(proto, f"proto {proto}"),
        "checksum":        f"0x{checksum:04x}",
        "checksum_valid":  verify_checksum(raw[offset:offset + ihl]),
        "src_ip":          ip_src,
        "dst_ip":          ip_dst,
    }

    transport_offset = offset + ihl
    parser = _TRANSPORT.get(proto)
    if parser:
        return parser(raw, transport_offset, result)

    result["protocol"] = PROTO_NAMES.get(proto, "IPv4")
    result["summary"]  = f"{result['protocol']} {ip_src} → {ip_dst}"
    return result
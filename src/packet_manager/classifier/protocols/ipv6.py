import struct
import ipaddress
from .tcp  import parse_tcp
from .udp  import parse_udp
from .icmp import parse_icmp  # ICMPv6 partilha estrutura base com ICMPv4

NH_HOPBYHOP = 0
NH_TCP      = 6
NH_UDP      = 17
NH_ROUTING  = 43
NH_FRAGMENT = 44
NH_ESP      = 50
NH_AUTH     = 51
NH_ICMPV6   = 58
NH_NONEXT   = 59
NH_DSTOPT   = 60

NH_NAMES = {
    NH_TCP: "TCP", NH_UDP: "UDP", NH_ICMPV6: "ICMPv6",
    NH_ESP: "ESP", NH_AUTH: "AH", NH_FRAGMENT: "Fragment",
}

_EXT_HEADERS = {NH_HOPBYHOP, NH_ROUTING, NH_DSTOPT, NH_AUTH}

_TRANSPORT: dict[int, callable] = {
    NH_TCP:    parse_tcp,
    NH_UDP:    parse_udp,
    NH_ICMPV6: parse_icmp,
}

ICMPv6_TYPE_NAMES = {
    1: "Destination Unreachable", 2: "Packet Too Big",
    3: "Time Exceeded",           4: "Parameter Problem",
    128: "Echo Request",          129: "Echo Reply",
    133: "Router Solicitation",   134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
    137: "Redirect",
}


def _skip_extension_headers(raw: bytes, offset: int, next_header: int) -> tuple[int, int]:
    """
    Percorre extension headers IPv6 até encontrar o protocolo de transporte.
    Retorna (next_header_final, offset_final).
    """
    while next_header in _EXT_HEADERS or next_header == NH_FRAGMENT:
        if len(raw) < offset + 2:
            break
        next_header_new = raw[offset]
        if next_header == NH_FRAGMENT:
            offset += 8        
        else:
            ext_len = (raw[offset + 1] + 1) * 8
            offset += ext_len
        next_header = next_header_new
    return next_header, offset


def parse_ipv6(raw: bytes, offset: int, result: dict) -> dict:
    if len(raw) < offset + 40:
        result["protocol"] = "IPv6"
        result["summary"]  = "IPv6 frame demasiado curto"
        return result

    ver_tc_fl    = struct.unpack("!I", raw[offset:offset + 4])[0]
    version      = ver_tc_fl >> 28
    traffic_class = (ver_tc_fl >> 20) & 0xFF
    flow_label   = ver_tc_fl & 0xFFFFF
    payload_len  = struct.unpack("!H", raw[offset + 4:offset + 6])[0]
    next_header  = raw[offset + 6]
    hop_limit    = raw[offset + 7]

    ip_src = str(ipaddress.IPv6Address(raw[offset + 8:offset + 24]))
    ip_dst = str(ipaddress.IPv6Address(raw[offset + 24:offset + 40]))

    result["ip_src"] = ip_src
    result["ip_dst"] = ip_dst
    result["details"]["ipv6"] = {
        "version":       version,
        "traffic_class": traffic_class,
        "flow_label":    f"0x{flow_label:05x}",
        "payload_length": payload_len,
        "next_header":   next_header,
        "next_header_name": NH_NAMES.get(next_header, f"nh {next_header}"),
        "hop_limit":     hop_limit,
        "src_ip":        ip_src,
        "dst_ip":        ip_dst,
    }

    transport_offset = offset + 40
    next_header, transport_offset = _skip_extension_headers(raw, transport_offset, next_header)

    if next_header == NH_ICMPV6 and len(raw) > transport_offset:
        icmp_type = raw[transport_offset]
        result["details"].setdefault("_icmpv6_hint", ICMPv6_TYPE_NAMES.get(icmp_type))

    parser = _TRANSPORT.get(next_header)
    if parser:
        result = parser(raw, transport_offset, result)
        if next_header == NH_ICMPV6:
            result["protocol"] = "ICMPv6"
            if "icmp" in result["details"]:
                t = result["details"]["icmp"]["type"]
                result["details"]["icmp"]["type_name"] = ICMPv6_TYPE_NAMES.get(t, f"type {t}")
                result["summary"] = result["summary"].replace(
                    f"ICMP type {t}", f"ICMPv6 {ICMPv6_TYPE_NAMES.get(t, f'type {t}')}"
                )
        return result

    nh_name = NH_NAMES.get(next_header, f"nh={next_header}")
    result["protocol"] = "IPv6"
    result["summary"]  = f"IPv6 {nh_name} {ip_src} → {ip_dst}"
    return result
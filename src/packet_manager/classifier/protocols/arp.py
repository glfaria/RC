import struct
import ipaddress
from ..utils import mac_to_str

OP_NAMES = {1: "request", 2: "reply"}


def parse_arp(raw: bytes, offset: int, result: dict) -> dict:
    result["protocol"] = "ARP"

    if len(raw) < offset + 8:
        result["summary"] = "ARP frame demasiado curto"
        return result

    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", raw[offset:offset + 8])
    p = offset + 8

    sha = raw[p:p + hlen]; p += hlen
    spa = raw[p:p + plen]; p += plen
    tha = raw[p:p + hlen]; p += hlen
    tpa = raw[p:p + plen]

    ip_src  = str(ipaddress.IPv4Address(spa)) if plen == 4 else spa.hex()
    ip_dst  = str(ipaddress.IPv4Address(tpa)) if plen == 4 else tpa.hex()
    op_name = OP_NAMES.get(oper, f"op {oper}")
    sha_str = mac_to_str(sha) if len(sha) == 6 else sha.hex()
    tha_str = mac_to_str(tha) if len(tha) == 6 else tha.hex()

    result["ip_src"] = ip_src
    result["ip_dst"] = ip_dst
    result["summary"] = (
        f"ARP {op_name}: who has {ip_dst}? Tell {ip_src}" if oper == 1 else
        f"ARP {op_name}: {ip_src} is at {sha_str}"        if oper == 2 else
        f"ARP {op_name}"
    )
    result["details"]["arp"] = {
        "htype": htype, "ptype": f"0x{ptype:04x}",
        "hlen": hlen,   "plen": plen, "op": oper, "op_name": op_name,
        "sender_mac": sha_str, "sender_ip": ip_src,
        "target_mac": tha_str, "target_ip": ip_dst,
    }
    return result
import struct
from ..utils import verify_checksum

TYPE_NAMES = {
    0: "Echo Reply",      3: "Destination Unreachable",
    8: "Echo Request",    11: "Time Exceeded",
    5: "Redirect",        12: "Parameter Problem",
}
UNREACH_CODES = {
    0: "Net Unreachable",  1: "Host Unreachable",
    2: "Protocol Unreachable", 3: "Port Unreachable",
    4: "Fragmentation Needed",
}


def parse_icmp(raw: bytes, offset: int, result: dict) -> dict:
    result["protocol"] = "ICMP"

    if len(raw) < offset + 4:
        result["summary"] = "ICMP demasiado curto"
        return result

    icmp_type = raw[offset]
    icmp_code = raw[offset + 1]
    checksum  = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
    type_name = TYPE_NAMES.get(icmp_type, f"type {icmp_type}")

    detail = {
        "type":           icmp_type,
        "type_name":      type_name,
        "code":           icmp_code,
        "checksum":       f"0x{checksum:04x}",
        "checksum_valid": verify_checksum(raw[offset:]),
    }

    if icmp_type in (0, 8) and len(raw) >= offset + 8:
        identifier, sequence = struct.unpack("!HH", raw[offset + 4:offset + 8])
        detail["identifier"] = identifier
        detail["sequence"]   = sequence
        result["summary"] = f"ICMP {type_name} id={identifier} seq={sequence}"
    elif icmp_type == 3:
        code_name = UNREACH_CODES.get(icmp_code, f"code {icmp_code}")
        detail["code_name"] = code_name
        result["summary"] = f"ICMP {type_name} ({code_name})"
    elif icmp_type == 11:
        code_name = "TTL exceeded" if icmp_code == 0 else "Fragment reassembly timeout"
        detail["code_name"] = code_name
        result["summary"] = f"ICMP {type_name} ({code_name})"
    else:
        result["summary"] = f"ICMP {type_name} code={icmp_code}"

    result["details"]["icmp"] = detail
    return result
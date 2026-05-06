import struct


def parse_stp(raw: bytes, offset: int, result: dict) -> dict:

    result["protocol"] = "STP"

    if len(raw) < offset + 4:
        result["summary"] = "STP frame demasiado curto"
        return result

    llc_offset = offset
    if len(raw) > llc_offset + 2 and raw[llc_offset] == 0x42 and raw[llc_offset + 1] == 0x42:
        offset = llc_offset + 3  

    if len(raw) < offset + 4:
        result["summary"] = "STP BPDU demasiado curto"
        return result

    proto_id  = struct.unpack("!H", raw[offset:offset + 2])[0]
    version   = raw[offset + 2]
    bpdu_type = raw[offset + 3]

    BPDU_TYPES = {0x00: "Configuration", 0x80: "TCN", 0x02: "RSTP/MSTP"}
    type_name  = BPDU_TYPES.get(bpdu_type, f"type 0x{bpdu_type:02x}")

    detail: dict = {
        "protocol_id": f"0x{proto_id:04x}",
        "version":     version,
        "bpdu_type":   bpdu_type,
        "bpdu_type_name": type_name,
    }

    if bpdu_type == 0x00 and len(raw) >= offset + 35:
        flags      = raw[offset + 4]
        root_pri   = struct.unpack("!H", raw[offset + 5:offset + 7])[0]
        root_mac   = ":".join(f"{b:02x}" for b in raw[offset + 7:offset + 13])
        root_cost  = struct.unpack("!I", raw[offset + 13:offset + 17])[0]
        bridge_pri = struct.unpack("!H", raw[offset + 17:offset + 19])[0]
        bridge_mac = ":".join(f"{b:02x}" for b in raw[offset + 19:offset + 25])
        port_id    = struct.unpack("!H", raw[offset + 25:offset + 27])[0]

        detail.update({
            "flags":       f"0x{flags:02x}",
            "root_priority": root_pri,
            "root_mac":    root_mac,
            "root_cost":   root_cost,
            "bridge_priority": bridge_pri,
            "bridge_mac":  bridge_mac,
            "port_id":     f"0x{port_id:04x}",
        })
        result["summary"] = (
            f"STP {type_name} Root={root_pri}/{root_mac} Cost={root_cost} Port=0x{port_id:04x}"
        )
    else:
        result["summary"] = f"STP {type_name}"

    result["details"]["stp"] = detail
    return result
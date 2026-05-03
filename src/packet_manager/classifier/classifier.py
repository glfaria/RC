import struct
import ipaddress
from datetime import datetime

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def classify_packet(raw: bytes) -> dict:
    data = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "length": len(raw),
        "protocol": "OTHER",
        "summary": "",
        "details": {}
    }

    if len(raw) < 14:
        data["summary"] = "Frame too short"
        return data

    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw[:14])

    data["mac_src"] = mac_to_str(src_mac)
    data["mac_dst"] = mac_to_str(dst_mac)
    data["details"]["ethernet"] = {
        "dst_mac": data["mac_dst"],
        "src_mac": data["mac_src"],
        "ethertype": f"0x{ethertype:04x}",
    }

    if ethertype == ETH_P_ARP:
        if len(raw) < 22:
            data["protocol"] = "ARP"
            data["summary"] = "ARP frame too short"
            return data

        offset = 14
        htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", raw[offset:offset + 8])
        p = offset + 8

        sha = raw[p:p + hlen]
        p += hlen
        spa = raw[p:p + plen]
        p += plen
        tha = raw[p:p + hlen]
        p += hlen
        tpa = raw[p:p + plen]

        ip_src = str(ipaddress.IPv4Address(spa)) if plen == 4 else spa.hex()
        ip_dst = str(ipaddress.IPv4Address(tpa)) if plen == 4 else tpa.hex()

        data["protocol"] = "ARP"
        data["ip_src"] = ip_src
        data["ip_dst"] = ip_dst
        data["summary"] = "ARP request" if oper == 1 else "ARP reply" if oper == 2 else f"ARP op {oper}"
        data["details"]["arp"] = {
            "htype": htype,
            "ptype": f"0x{ptype:04x}",
            "hlen": hlen,
            "plen": plen,
            "op": oper,
            "sender_mac": mac_to_str(sha) if len(sha) == 6 else sha.hex(),
            "sender_ip": ip_src,
            "target_mac": mac_to_str(tha) if len(tha) == 6 else tha.hex(),
            "target_ip": ip_dst,
        }
        return data

    if ethertype == ETH_P_IP:
        if len(raw) < 34:
            data["protocol"] = "IPv4"
            data["summary"] = "IPv4 frame too short"
            return data

        ip_off = 14
        ver_ihl = raw[ip_off]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4

        if version != 4:
            data["summary"] = f"Unexpected IP version {version}"
            return data

        total_length = struct.unpack("!H", raw[ip_off + 2:ip_off + 4])[0]
        identification = struct.unpack("!H", raw[ip_off + 4:ip_off + 6])[0]
        flags_frag = struct.unpack("!H", raw[ip_off + 6:ip_off + 8])[0]
        ttl = raw[ip_off + 8]
        proto = raw[ip_off + 9]
        checksum = struct.unpack("!H", raw[ip_off + 10:ip_off + 12])[0]

        ip_src = str(ipaddress.IPv4Address(raw[ip_off + 12:ip_off + 16]))
        ip_dst = str(ipaddress.IPv4Address(raw[ip_off + 16:ip_off + 20]))

        data["ip_src"] = ip_src
        data["ip_dst"] = ip_dst
        data["details"]["ipv4"] = {
            "version": version,
            "ihl": ihl,
            "tos": raw[ip_off + 1],
            "total_length": total_length,
            "identification": identification,
            "flags_fragment": flags_frag,
            "ttl": ttl,
            "protocol": proto,
            "checksum": f"0x{checksum:04x}",
            "src_ip": ip_src,
            "dst_ip": ip_dst,
        }

        transport_off = ip_off + ihl

        if proto == IPPROTO_ICMP:
            data["protocol"] = "ICMP"
            if len(raw) >= transport_off + 4:
                icmp_type = raw[transport_off]
                icmp_code = raw[transport_off + 1]
                icmp_checksum = struct.unpack("!H", raw[transport_off + 2:transport_off + 4])[0]
                data["details"]["icmp"] = {
                    "type": icmp_type,
                    "code": icmp_code,
                    "checksum": f"0x{icmp_checksum:04x}",
                }
                data["summary"] = f"ICMP type {icmp_type} code {icmp_code}"
            else:
                data["summary"] = "ICMP packet"
            return data

        if proto == IPPROTO_TCP:
            data["protocol"] = "TCP"
            if len(raw) >= transport_off + 20:
                src_port, dst_port = struct.unpack("!HH", raw[transport_off:transport_off + 4])
                seq = struct.unpack("!I", raw[transport_off + 4:transport_off + 8])[0]
                ack = struct.unpack("!I", raw[transport_off + 8:transport_off + 12])[0]
                offset_flags = struct.unpack("!H", raw[transport_off + 12:transport_off + 14])[0]
                window = struct.unpack("!H", raw[transport_off + 14:transport_off + 16])[0]
                checksum = struct.unpack("!H", raw[transport_off + 16:transport_off + 18])[0]
                urgent = struct.unpack("!H", raw[transport_off + 18:transport_off + 20])[0]

                data["details"]["tcp"] = {
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "sequence": seq,
                    "acknowledgment": ack,
                    "offset_flags": offset_flags,
                    "window": window,
                    "checksum": f"0x{checksum:04x}",
                    "urgent_pointer": urgent,
                }
                data["summary"] = f"TCP {src_port} -> {dst_port}"
            else:
                data["summary"] = "TCP segment"
            return data

        if proto == IPPROTO_UDP:
            data["protocol"] = "UDP"
            if len(raw) >= transport_off + 8:
                src_port, dst_port, udp_len, udp_checksum = struct.unpack("!HHHH", raw[transport_off:transport_off + 8])
                data["details"]["udp"] = {
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": udp_len,
                    "checksum": f"0x{udp_checksum:04x}",
                }
                data["summary"] = f"UDP {src_port} -> {dst_port}"
            else:
                data["summary"] = "UDP datagram"
            return data

        data["protocol"] = "IPv4"
        data["summary"] = f"IPv4 protocol {proto}"
        return data

    data["summary"] = f"EtherType 0x{ethertype:04x}"
    return data
"""
Para adicionar um novo protocolo de rede:
  1. Criar protocols/meu_proto.py com parse_meu_proto(raw, offset, result)
  2. Importar e adicionar ao dict _NETWORK_PARSERS abaixo.
"""

import struct
from ..utils import mac_to_str
from .arp  import parse_arp
from .ipv4 import parse_ipv4
from .ipv6 import parse_ipv6
from .stp  import parse_stp

ETH_P_IP  = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IP6 = 0x86DD

ETHERTYPE_NAMES = {
    ETH_P_IP:  "IPv4",
    ETH_P_ARP: "ARP",
    ETH_P_IP6: "IPv6",
    0x8100: "VLAN",
    0x88CC: "LLDP",
    0x8847: "MPLS",
}

# Adicionar aqui para suportar novos protocolos de camada 3.
_NETWORK_PARSERS: dict[int, callable] = {
    ETH_P_IP:  parse_ipv4,
    ETH_P_ARP: parse_arp,
    ETH_P_IP6: parse_ipv6,
}

_LLC_ETHERTYPES = {0x002E, 0x0026} 


def parse_ethernet(raw: bytes, result: dict) -> dict:
    if len(raw) < 14:
        result["summary"] = "Frame demasiado curto"
        return result

    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw[:14])

    result["mac_src"] = mac_to_str(src_mac)
    result["mac_dst"] = mac_to_str(dst_mac)
    result["details"]["ethernet"] = {
        "dst_mac":       result["mac_dst"],
        "src_mac":       result["mac_src"],
        "ethertype":     f"0x{ethertype:04x}",
        "ethertype_name": ETHERTYPE_NAMES.get(ethertype, "UNKNOWN"),
    }

    if ethertype < 0x0600 or ethertype in _LLC_ETHERTYPES:
        return _parse_llc(raw, 14, ethertype, result)

    parser = _NETWORK_PARSERS.get(ethertype)
    if parser:
        return parser(raw, 14, result)

    result["summary"] = f"EtherType 0x{ethertype:04x} ({ETHERTYPE_NAMES.get(ethertype, 'UNKNOWN')})"
    return result


def _parse_llc(raw: bytes, offset: int, ethertype: int, result: dict) -> dict:
    """Trata frames com LLC header (802.2). Identifica STP pelo DSAP=0x42."""
    if len(raw) < offset + 3:
        result["summary"] = f"LLC frame demasiado curto (0x{ethertype:04x})"
        return result

    dsap = raw[offset]
    ssap = raw[offset + 1]

    if dsap == 0x42 and ssap == 0x42:
        return parse_stp(raw, offset, result)

    if dsap == 0xAA and ssap == 0xAA and len(raw) >= offset + 8:
        snap_type = struct.unpack("!H", raw[offset + 6:offset + 8])[0]
        parser = _NETWORK_PARSERS.get(snap_type)
        if parser:
            return parser(raw, offset + 8, result)

    result["summary"] = f"LLC DSAP=0x{dsap:02x} SSAP=0x{ssap:02x}"
    return result
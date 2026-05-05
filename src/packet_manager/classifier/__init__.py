from datetime import datetime
from .protocols import parse_ethernet

def classify_packet(raw: bytes) -> dict:
    if not raw:
        return {}

    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "length":    len(raw),
        "protocol":  "OTHER",
        "summary":   "",
        "details":   {},
    }

    parse_ethernet(raw, result)

    if not result["summary"]:
        result["summary"] = f"EtherType desconhecido"

    return result
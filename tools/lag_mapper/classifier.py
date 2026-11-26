"""MLBB server IP classification, confidence tagging, and regional map cluster coordinates."""

from __future__ import annotations

import ipaddress
from typing import Any

from tools.draft_probe import IFACE_NAMES, IGNORED_PORTS, KNOWN_IP, PREFIX_HINTS, PRIVATE_V4, PROBE_PORT

# SVG hub coordinates on an 800x360 regional map viewBox (West=left, East=right).
CITY_CLUSTERS: dict[str, dict[str, Any]] = {
    "surabaya": {"label": "Surabaya (You)", "x": 430, "y": 298},
    "jakarta": {"label": "Jakarta", "x": 368, "y": 282},
    "singapore": {"label": "Singapore", "x": 336, "y": 234},
    "kuala_lumpur": {"label": "Kuala Lumpur", "x": 286, "y": 200},
    "bangkok": {"label": "Bangkok", "x": 298, "y": 146},
    "manila": {"label": "Manila", "x": 512, "y": 168},
    "india": {"label": "India (Mumbai/Delhi)", "x": 182, "y": 148},
    "almaty": {"label": "Almaty", "x": 216, "y": 74},
    "istanbul": {"label": "Istanbul", "x": 108, "y": 82},
    "tokyo": {"label": "Tokyo", "x": 608, "y": 116},
    "sydney": {"label": "Sydney", "x": 632, "y": 308},
    "dallas": {"label": "Dallas / US", "x": 726, "y": 94},
    "europe_unknown": {"label": "Europe / Unknown", "x": 76, "y": 162},
}

_OBSERVED_SUBNETS: tuple[tuple[str, str, str, str], ...] = (
    ("149.104.112.", "Observed", "Observed (Singapore/BGP?)", "observed subnet; provider unverified"),
)

__all__ = [
    "CITY_CLUSTERS",
    "IFACE_NAMES",
    "IGNORED_PORTS",
    "KNOWN_IP",
    "PREFIX_HINTS",
    "PRIVATE_V4",
    "PROBE_PORT",
    "city_to_cluster",
    "classify_ip",
    "is_public_ipv4",
    "subnet_24",
]


def is_public_ipv4(addr: str) -> bool:
    """Return True if *addr* is a valid globally routable IPv4 address."""
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return False
    return not any(ip in net for net in PRIVATE_V4)


def subnet_24(ip: str) -> str:
    """Return the `/24` prefix label for an IPv4 string."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip


def city_to_cluster(city: str) -> str:
    """Map a city or geo label to a fixed `CITY_CLUSTERS` key."""
    low = city.lower()
    if "jakarta" in low:
        return "jakarta"
    if "singapore" in low:
        return "singapore"
    if "kuala lumpur" in low or low == "kl":
        return "kuala_lumpur"
    if "bangkok" in low:
        return "bangkok"
    if "manila" in low:
        return "manila"
    if "delhi" in low or "mumbai" in low or "india" in low:
        return "india"
    if "almaty" in low:
        return "almaty"
    if "istanbul" in low:
        return "istanbul"
    if "tokyo" in low:
        return "tokyo"
    if "sydney" in low:
        return "sydney"
    if "dallas" in low or "miami" in low or low.endswith(" us") or low == "us":
        return "dallas"
    return "europe_unknown"


def classify_ip(ip: str) -> dict[str, Any]:
    """Classify a remote server IP using `KNOWN_IP`, `PREFIX_HINTS`, and observed subnets."""
    if ip in KNOWN_IP:
        prov, city, note = KNOWN_IP[ip]
        confidence = "known"
    else:
        matched_prefix = None
        for prefix, p_prov, p_city in PREFIX_HINTS:
            if ip.startswith(prefix):
                matched_prefix = (p_prov, p_city)
                break
        if matched_prefix is not None:
            prov, city = matched_prefix
            if prov == "unknown":
                prov = "Observed"
            note = "prefix match only"
            confidence = "prefix"
        else:
            obs = next((row for row in _OBSERVED_SUBNETS if ip.startswith(row[0])), None)
            if obs is not None:
                _, prov, city, note = obs
                confidence = "observed"
            else:
                prov, city, note, confidence = "Observed", "Unknown", "unmapped public IP", "observed"

    cluster_key = city_to_cluster(city)
    cluster = CITY_CLUSTERS[cluster_key]
    return {
        "ip": ip,
        "subnet": subnet_24(ip),
        "provider": prov,
        "city": city,
        "note": note,
        "confidence": confidence,
        "cluster_key": cluster_key,
        "approx_coords": {"x": cluster["x"], "y": cluster["y"], "label": cluster["label"]},
    }

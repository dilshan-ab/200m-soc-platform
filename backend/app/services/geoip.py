"""GeoIP lookup using MaxMind GeoLite2-City database."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

log = logging.getLogger("soc.geoip")

_reader = None
_GEOIP_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "GeoLite2-City.mmdb"

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return True


def init() -> bool:
    global _reader
    if _reader is not None:
        return True
    if not _GEOIP_PATH.exists():
        log.warning("GeoLite2-City.mmdb not found at %s – threat map will use fallback", _GEOIP_PATH)
        return False
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(str(_GEOIP_PATH))
        log.info("GeoIP database loaded: %s", _GEOIP_PATH)
        return True
    except Exception:
        log.exception("Failed to load GeoIP database")
        return False


def lookup(ip: str) -> dict | None:
    if not ip or _is_private(ip):
        return None
    if _reader is None:
        return None
    try:
        r = _reader.city(ip)
        if r.location.latitude is None or r.location.longitude is None:
            return None
        return {
            "lat": r.location.latitude,
            "lng": r.location.longitude,
            "country": r.country.iso_code or "XX",
            "country_name": r.country.name or "Unknown",
            "city": r.city.name or "",
        }
    except Exception:
        return None

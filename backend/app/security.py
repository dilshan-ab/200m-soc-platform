"""Cryptographic and network-safety primitives."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import get_settings

_ph = PasswordHasher()


class SecurityError(ValueError):
    pass


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hashed: str | None, password: str) -> bool:
    if not hashed:
        # burn comparable time to avoid user enumeration
        try:
            _ph.verify(_DUMMY, password)
        except (VerificationError, InvalidHashError):
            pass
        return False
    try:
        return _ph.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


_DUMMY = _ph.hash("dummy-password-for-timing")


def password_policy_ok(password: str) -> bool:
    return (
        len(password) >= 12
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def payload_hash(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def hmac_sha256(key: str | bytes, msg: str | bytes) -> str:
    if isinstance(key, str):
        key = key.encode()
    if isinstance(msg, str):
        msg = msg.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ TOTP (dev mode)
def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str | None, code: str) -> bool:
    if not secret or not code or not code.isdigit():
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


# ------------------------------------------------------------------ SSRF / egress policy
_ALWAYS_BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8")
]

Resolver = Callable[[str], list[str]]


def _default_resolve(host: str) -> list[str]:
    try:
        return sorted({str(ai[4][0]) for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        raise SecurityError(f"cannot resolve host {host}") from e


def validate_egress_url(url: str, *, resolver: Resolver | None = None, allow_loopback: bool = False) -> str:
    """Raise SecurityError unless `url` is https (or http when explicitly allowed), has no
    credentials, and resolves only to approved internal networks."""
    s = get_settings()
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise SecurityError("only http(s) URLs are allowed")
    if parts.scheme == "http" and not s.allow_http_connectors:
        raise SecurityError("plain http is not allowed; use https")
    if parts.username or parts.password:
        raise SecurityError("credentials in URLs are not allowed")
    host = parts.hostname
    if not host:
        raise SecurityError("URL has no host")
    allowed_nets = [ipaddress.ip_network(c) for c in s.egress_allowed_cidrs]
    host_l = host.lower()
    try:
        addrs = [str(ipaddress.ip_address(host_l))]
        literal = True
    except ValueError:
        literal = False
        addrs = (resolver or _default_resolve)(host_l)
    if not literal and not any(host_l.endswith(suf.lower()) for suf in s.egress_allowed_suffixes):
        if not all(_in_nets(a, allowed_nets) for a in addrs):
            raise SecurityError("host is not in an approved internal domain or network")
    if not addrs:
        raise SecurityError("host did not resolve")
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if ip.is_loopback and allow_loopback:
            continue
        if any(ip in n for n in _ALWAYS_BLOCKED_NETS):
            raise SecurityError("destination address is blocked")
        if literal and not _in_nets(a, allowed_nets):
            raise SecurityError("address is outside approved networks")
    return url


def _in_nets(addr: str, nets: list[Any]) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip in n for n in nets)


def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback

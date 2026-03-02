import ipaddress
from typing import Union

from app import config

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address((ip or "").strip())
        return True
    except ValueError:
        return False


def _parse_allowlist(raw: str) -> list[Network]:
    networks: list[Network] = []
    for item in [part.strip() for part in (raw or "").split(",") if part.strip()]:
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
                continue

            address = ipaddress.ip_address(item)
            suffix = "/32" if address.version == 4 else "/128"
            networks.append(ipaddress.ip_network(f"{item}{suffix}", strict=False))
        except ValueError:
            continue
    return networks


def is_allowed_scan_target(ip: str) -> bool:
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False

    if address.is_loopback or address.is_private or address.is_link_local:
        return True

    if config.SCAN_ALLOW_PUBLIC_TARGETS:
        return True

    return any(address in network for network in _parse_allowlist(config.SCAN_TARGET_ALLOWLIST))


def ensure_allowed_scan_target(ip: str) -> str:
    normalized_ip = (ip or "").strip()
    if not is_valid_ip(normalized_ip):
        raise ValueError("Invalid target IP address")
    if not is_allowed_scan_target(normalized_ip):
        raise ValueError(
            "Target IP is outside allowed scan scope. Public targets are blocked by default."
        )
    return normalized_ip

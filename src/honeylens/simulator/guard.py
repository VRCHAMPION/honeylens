"""Guardrails: the live simulator may ONLY connect to safe, local targets.

Allowed targets:

1. loopback addresses (127.0.0.0/8, ::1) - your own laptop,
2. a Docker Compose service name of THIS project (default: ``cowrie``) that
   resolves to a private address - i.e. a container on the project network,
3. a host listed exactly in ``HL_SIM_ALLOWED_HOSTS`` in ``.env`` - for a
   honeypot you own; still blocked if it resolves to a multicast/reserved IP.

Everything else is refused BEFORE any packet is sent. This prevents the tool
from ever being pointed at a third party (which would be illegal scanning).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable


class TargetNotAllowed(PermissionError):
    """Raised when the requested target is not on the allow-list."""


def _split(value: str) -> set[str]:
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def check_target(
    host: str,
    resolver: Callable[[str], list[str]] | None = None,
    allowed_hosts: str | None = None,
    compose_services: str | None = None,
) -> str:
    """Return the IP to connect to, or raise :class:`TargetNotAllowed`."""
    if not host or len(host) > 253:
        raise TargetNotAllowed("empty or invalid target")
    name = host.strip().lower()
    allowed = _split(allowed_hosts if allowed_hosts is not None else os.environ.get("HL_SIM_ALLOWED_HOSTS", ""))
    services = _split(
        compose_services if compose_services is not None else os.environ.get("HL_SIM_COMPOSE_SERVICES", "cowrie")
    )
    resolve = resolver or _resolve
    try:
        ips = [ipaddress.ip_address(name)]
    except ValueError:
        # Do not resolve arbitrary names: DNS itself sends traffic before an
        # unapproved target could otherwise be rejected. Only local service
        # names and exact operator allow-list entries may be looked up.
        if name == "localhost":
            return "127.0.0.1"
        if name not in services and name not in allowed:
            raise TargetNotAllowed(
                f"target {host} is not on the local service or HL_SIM_ALLOWED_HOSTS allow-list"
            ) from None
        try:
            ips = [ipaddress.ip_address(x) for x in resolve(name)]
        except OSError as exc:
            raise TargetNotAllowed(f"cannot resolve {host}") from exc
    if not ips:
        raise TargetNotAllowed(f"{host} did not resolve")
    for ip in ips:
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise TargetNotAllowed(f"{host} resolves to a forbidden address {ip}")
    if all(ip.is_loopback for ip in ips):
        return str(ips[0])
    if name in services and all(ip.is_private and not ip.is_loopback for ip in ips):
        return str(ips[0])  # a container on the project's private Docker network
    if name in allowed:
        return str(ips[0])
    raise TargetNotAllowed(
        f"target {host} ({', '.join(map(str, ips))}) is not loopback, not a project service, "
        "and not in HL_SIM_ALLOWED_HOSTS - refusing to connect"
    )


def _resolve(name: str) -> list[str]:
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})

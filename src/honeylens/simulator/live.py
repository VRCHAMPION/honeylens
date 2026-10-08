"""Live mode: real SSH sessions against the local Cowrie honeypot ONLY.

Every target goes through :func:`honeylens.simulator.guard.check_target` first.
Sessions use the same personas as synthetic mode, so dashboards look alike.
Bots send commands quickly; "human" personas wait a few seconds between
commands (scaled by ``--speed`` so tests stay fast).
"""

from __future__ import annotations

import logging
import random
import socket
import time
from dataclasses import dataclass

import paramiko

from honeylens.simulator.guard import check_target
from honeylens.simulator.personas import PERSONAS, Persona

log = logging.getLogger("honeylens.simulator")


@dataclass
class LiveResult:
    """What one live session did."""

    persona: str
    connected: bool
    logged_in: bool
    commands_sent: int
    error: str = ""


def _gap(rng: random.Random, persona: Persona, speed: float) -> float:
    lo, hi = (0.1, 0.6) if persona.style == "bot" else (2.5, 6.0)
    return rng.uniform(lo, hi) / max(speed, 0.01)


def _banner_only(ip: str, port: int, timeout: float) -> LiveResult:
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.recv(256)  # read the SSH banner, then hang up like a scanner
        sock.sendall(b"SSH-2.0-Go\r\n")
    return LiveResult("scanner", True, False, 0)


def run_session(ip: str, port: int, persona: Persona, rng: random.Random, speed: float = 1.0,
                timeout: float = 10.0) -> LiveResult:
    """Run one persona against an ALREADY-VALIDATED ip."""
    if not persona.logins:
        return _banner_only(ip, port, timeout)
    sock = socket.create_connection((ip, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    transport.local_version = persona.client_version
    result = LiveResult(persona.name, True, False, 0)
    try:
        # We do not verify the host key: the target is our own honeypot (guard-checked).
        transport.start_client(timeout=timeout)
        for user, pw in persona.logins:
            try:
                transport.auth_password(user, pw)
            except paramiko.AuthenticationException:
                time.sleep(_gap(rng, persona, speed) / 3)
                continue
            if transport.is_authenticated():
                result.logged_in = True
                break
        if result.logged_in:
            chan = transport.open_session(timeout=timeout)
            chan.get_pty()
            chan.invoke_shell()
            time.sleep(0.5)
            for cmd in persona.commands:
                chan.send((cmd + "\n").encode())
                result.commands_sent += 1
                time.sleep(_gap(rng, persona, speed))
                while chan.recv_ready():
                    chan.recv(65536)
            chan.close()
    except (paramiko.SSHException, OSError) as exc:
        result.error = type(exc).__name__
    finally:
        transport.close()
    return result


def run_live(target: str, port: int, sessions: int, seed: int, speed: float = 1.0,
             personas: list[str] | None = None) -> list[LiveResult]:
    """Validate the target, then run ``sessions`` sessions cycling through personas."""
    ip = check_target(target)  # raises TargetNotAllowed BEFORE any connection
    if not 1 <= port <= 65535:
        raise ValueError("bad port")
    rng = random.Random(seed)  # nosec B311
    chosen = [p for p in PERSONAS if not personas or p.name in personas]
    results = []
    for i in range(sessions):
        persona = chosen[i % len(chosen)]
        try:
            res = run_session(ip, port, persona, rng, speed)
        except OSError as exc:
            res = LiveResult(persona.name, False, False, 0, type(exc).__name__)
        log.info("live session", extra={"persona": res.persona, "logged_in": res.logged_in,
                                        "commands": res.commands_sent, "error": res.error})
        results.append(res)
    return results

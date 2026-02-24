import re
import shutil
import socket
import subprocess

OPEN_TCP_PORT_REGEX = re.compile(r"(\d+)/open/tcp")


def _scan_tcp_port(target: str, port: int, timeout_sec: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_sec)
        result = sock.connect_ex((target, port))
        return result == 0
    except OSError:
        return False
    finally:
        sock.close()


def _discover_with_socket_fallback(
    *,
    target: str,
    ports: list[int],
    timeout_ms: int,
) -> list[int]:
    timeout_sec = timeout_ms / 1000.0
    return [port for port in ports if _scan_tcp_port(target, port, timeout_sec)]


def _discover_with_nmap(
    *,
    target: str,
    ports: list[int],
    timeout_ms: int,
) -> list[int]:
    port_arg = ",".join(str(port) for port in ports)
    host_timeout_ms = max(1000, min(300000, timeout_ms * max(1, len(ports))))
    command = [
        "nmap",
        "-n",
        "-Pn",
        "--open",
        "-p",
        port_arg,
        "--host-timeout",
        f"{host_timeout_ms}ms",
        "-oG",
        "-",
        target,
    ]
    process_timeout_sec = max(5, int(host_timeout_ms / 1000) + 5)
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=process_timeout_sec,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"nmap exited with code {completed.returncode}")

    open_ports = {int(match.group(1)) for match in OPEN_TCP_PORT_REGEX.finditer(completed.stdout or "")}
    return sorted(open_ports)


def discover_open_tcp_ports(
    *,
    target: str,
    ports: list[int],
    timeout_ms: int,
) -> tuple[list[int], str]:
    if shutil.which("nmap"):
        try:
            return _discover_with_nmap(target=target, ports=ports, timeout_ms=timeout_ms), "nmap"
        except Exception:
            # Keep scanning flow deterministic even if nmap executable is unavailable/broken.
            pass

    return _discover_with_socket_fallback(target=target, ports=ports, timeout_ms=timeout_ms), "socket-fallback"

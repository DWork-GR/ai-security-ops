import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

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


def is_nmap_available() -> bool:
    return bool(shutil.which("nmap"))


def ensure_nmap_available() -> None:
    if not is_nmap_available():
        raise RuntimeError(
            "Real scanning requires the 'nmap' binary. Install it or enable NMAP_ALLOW_SOCKET_FALLBACK=true."
        )


def inspect_open_tcp_services(
    *,
    target: str,
    ports: list[int],
    timeout_ms: int,
    include_vuln_scripts: bool = False,
) -> tuple[list[int], dict[int, str], dict[int, list[str]], str]:
    ensure_nmap_available()

    port_arg = ",".join(str(port) for port in ports)
    host_timeout_ms = max(1000, min(300000, timeout_ms * max(1, len(ports))))
    command = [
        "nmap",
        "-n",
        "-Pn",
        "--open",
        "-sV",
        "-p",
        port_arg,
        "--host-timeout",
        f"{host_timeout_ms}ms",
        "-oX",
        "-",
    ]
    if include_vuln_scripts:
        command.extend(["--script", "vuln"])
    command.append(target)

    process_timeout_sec = max(5, int(host_timeout_ms / 1000) + 10)
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=process_timeout_sec,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"nmap exited with code {completed.returncode}")

    try:
        root = ET.fromstring(completed.stdout or "<nmaprun />")
    except ET.ParseError as exc:
        raise RuntimeError("nmap produced invalid XML output") from exc

    open_ports: list[int] = []
    services: dict[int, str] = {}
    script_notes: dict[int, list[str]] = {}

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue

            try:
                port = int(port_el.attrib.get("portid", "0"))
            except ValueError:
                continue
            if port <= 0:
                continue

            open_ports.append(port)

            service_el = port_el.find("service")
            if service_el is not None:
                service_name = (
                    service_el.attrib.get("name")
                    or service_el.attrib.get("product")
                    or ""
                ).strip()
                if service_name:
                    services[port] = service_name.lower()

            notes = []
            for script_el in port_el.findall("script"):
                output = (script_el.attrib.get("output") or "").strip()
                script_id = (script_el.attrib.get("id") or "").strip()
                if output and script_id:
                    notes.append(f"{script_id}: {output}")
                elif output:
                    notes.append(output)
                elif script_id:
                    notes.append(script_id)
            if notes:
                script_notes[port] = notes

    engine = "nmap-vuln" if include_vuln_scripts else "nmap"
    return sorted(set(open_ports)), services, script_notes, engine


def discover_open_tcp_ports(
    *,
    target: str,
    ports: list[int],
    timeout_ms: int,
) -> tuple[list[int], str]:
    if is_nmap_available():
        try:
            return _discover_with_nmap(target=target, ports=ports, timeout_ms=timeout_ms), "nmap"
        except Exception:
            # Keep scanning flow deterministic even if nmap executable is unavailable/broken.
            pass

    return _discover_with_socket_fallback(target=target, ports=ports, timeout_ms=timeout_ms), "socket-fallback"

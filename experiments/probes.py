"""
Инструменты зондирования для экспериментального стенда.

- HTTP-пробы (curl через requests/httpx)
- ICMP ping (через subprocess)
- TCP port scan (nmap через subprocess)
"""

import subprocess
import time
from typing import Optional, Dict, Any

import httpx


def http_probe(url: str, auth: Optional[tuple] = None, verify_ssl: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
    """HTTP GET проба с фиксацией latency."""
    start = time.time()
    try:
        resp = httpx.get(url, auth=auth, verify=verify_ssl, timeout=timeout)
        latency = time.time() - start
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "latency_ms": round(latency * 1000, 2),
            "error": None,
        }
    except Exception as e:
        latency = time.time() - start
        return {
            "reachable": False,
            "status_code": None,
            "latency_ms": round(latency * 1000, 2),
            "error": str(e),
        }


def ping_probe(host: str, count: int = 3) -> Dict[str, Any]:
    """ICMP ping проба."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-q", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Парсинг среднего RTT из вывода
        rtt = None
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "rtt min/avg/max/mdev" in line:
                    parts = line.split("=")[1].strip().split("/")
                    rtt = float(parts[1])  # avg
        return {
            "reachable": result.returncode == 0,
            "rtt_avg_ms": rtt,
            "error": None if result.returncode == 0 else result.stderr,
        }
    except Exception as e:
        return {
            "reachable": False,
            "rtt_avg_ms": None,
            "error": str(e),
        }


def nmap_probe(host: str, ports: Optional[str] = None) -> Dict[str, Any]:
    """nmap сканирование портов."""
    cmd = ["nmap", "-Pn", "-T4"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(host)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        open_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and ("open" in line or "filtered" in line):
                port = line.split("/")[0].strip()
                state = "open" if "open" in line else "filtered"
                open_ports.append({"port": port, "state": state})
        return {
            "scanned": True,
            "open_ports": open_ports,
            "raw": result.stdout,
            "error": None,
        }
    except Exception as e:
        return {
            "scanned": False,
            "open_ports": [],
            "raw": "",
            "error": str(e),
        }

"""
TUN-шифратор клиентского агента (Direct-ZTNA).

Реализует L3-туннель поверх UDP с AES-256-GCM (через cryptography/OpenSSL).
- Создаёт TUN-интерфейс, маршрутизирует allowed_ips через него.
- Шифрует исходящие IP-пакеты в UDP-датаграммы.
- Расшифровывает входящие UDP-датаграммы и пишет в TUN.
- Keepalive каждые 25 секунд для поддержания NAT-pinhole.

Может работать как модуль (TunnelClient) или как standalone daemon.
"""

import base64
import fcntl
import os
import select
import socket
import struct
import threading
import time
from typing import List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

KEEPALIVE_INTERVAL_SEC = 25.0
PID_FILE = "/tmp/tunnel_daemon.pid"


def create_tun(dev_name: str) -> int:
    """Создать persistent TUN-интерфейс через ioctl."""
    os.system(f"ip tuntap add mode tun {dev_name} 2>/dev/null")
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", dev_name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


class TunnelClient:
    """Клиентский forwarder: TUN ↔ UDP."""

    def __init__(
        self,
        server_endpoint: str,
        key_b64: str,
        allowed_ips: List[str],
        tun_dev: str = "tun0",
        tun_ip: str = "10.200.200.2/24",
    ):
        host, port = server_endpoint.rsplit(":", 1)
        self.server_addr = (host, int(port))
        self.key = base64.b64decode(key_b64)
        self.aesgcm = AESGCM(self.key)
        self.allowed_ips = allowed_ips
        self.tun_dev = tun_dev
        self.tun_ip = tun_ip
        self.sock: Optional[socket.socket] = None
        self.tun_fd: Optional[int] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Создать TUN, настроить маршруты и запустить forwarder."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.tun_fd = create_tun(self.tun_dev)
        os.system(f"ip addr add {self.tun_ip} dev {self.tun_dev} 2>/dev/null")
        os.system(f"ip link set mtu 1280 dev {self.tun_dev} 2>/dev/null")
        os.system(f"ip link set up dev {self.tun_dev} 2>/dev/null")
        for ip in self.allowed_ips:
            os.system(f"ip route add {ip} dev {self.tun_dev} 2>/dev/null")
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._keepalive_thread = threading.Thread(target=self._keepalive, daemon=True)
        self._keepalive_thread.start()

    def stop(self) -> None:
        """Остановить forwarder и удалить TUN."""
        self._running = False
        if self.sock:
            self.sock.close()
        if self.tun_fd:
            os.close(self.tun_fd)
            os.system(f"ip link del {self.tun_dev} 2>/dev/null")

    def _keepalive(self) -> None:
        """Периодически посылать пустой зашифрованный пакет."""
        while self._running:
            time.sleep(KEEPALIVE_INTERVAL_SEC)
            if not self._running:
                break
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, b"", None)
            try:
                self.sock.sendto(nonce + ciphertext, self.server_addr)
            except OSError:
                pass

    def _run(self) -> None:
        while self._running:
            try:
                readable, _, _ = select.select([self.sock, self.tun_fd], [], [], 1.0)
            except (ValueError, OSError):
                break
            for fd in readable:
                if fd == self.sock:
                    try:
                        data, _ = self.sock.recvfrom(2048)
                        self._handle_inbound(data)
                    except socket.timeout:
                        pass
                    except OSError:
                        pass
                elif fd == self.tun_fd:
                    try:
                        packet = os.read(self.tun_fd, 2048)
                        self._handle_outbound(packet)
                    except OSError:
                        pass

    def _handle_inbound(self, data: bytes) -> None:
        """UDP → TUN."""
        if len(data) < 28:
            return
        nonce = data[:12]
        ciphertext = data[12:]
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            if plaintext:
                os.write(self.tun_fd, plaintext)
        except Exception:
            pass  # Drop invalid packets

    def _handle_outbound(self, packet: bytes) -> None:
        """TUN → UDP."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, packet, None)
        try:
            self.sock.sendto(nonce + ciphertext, self.server_addr)
        except OSError:
            pass


def _write_pid() -> None:
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def _read_pid() -> Optional[int]:
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return None


def stop_daemon() -> None:
    """Остановить detached daemon по PID-файлу."""
    pid = _read_pid()
    if pid:
        try:
            os.kill(pid, 15)  # SIGTERM
            # Wait up to 300 ms for graceful shutdown
            for _ in range(6):
                time.sleep(0.05)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
        except ProcessLookupError:
            pass
    try:
        os.remove(PID_FILE)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Direct-ZTNA TUN Daemon")
    parser.add_argument("--endpoint", required=True, help="Server endpoint IP:port")
    parser.add_argument("--key", required=True, help="PSK base64")
    parser.add_argument("--allowed-ips", required=True, help="Comma-separated CIDR list")
    parser.add_argument("--tun-dev", default="tun0", help="TUN device name")
    parser.add_argument("--tun-ip", default="10.200.200.2/24", help="TUN IP address")
    args = parser.parse_args()

    _write_pid()
    client = TunnelClient(
        server_endpoint=args.endpoint,
        key_b64=args.key,
        allowed_ips=args.allowed_ips.split(","),
        tun_dev=args.tun_dev,
        tun_ip=args.tun_ip,
    )
    client.start()

    _running_main = True

    def _on_sigterm(signum, frame):
        print(f"[tunnel] Received signal {signum}, shutting down...", flush=True)
        global _running_main
        _running_main = False
        client.stop()

    print("[tunnel] Registering signal handlers...", flush=True)
    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, _on_sigterm)
    print("[tunnel] Signal handlers registered.", flush=True)

    # Блокируем основной поток — проверяем флаг каждую секунду
    while _running_main:
        time.sleep(1)

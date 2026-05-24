"""
TUN-шифратор серверного агента (Direct-ZTNA).

Реализует L3-туннель поверх UDP с AES-256-GCM (через cryptography/OpenSSL).
- Multi-client: сервер слушает один UDP-порт, расшифровывает пакеты перебором
  активных ключей (O(N) на пакет, для прототипа — приемлемо).
- Silent drop: при отсутствии ключа пакет тихо отбрасывается.
- Добавление/удаление peer — операция в памяти (микросекунды).
"""

import base64
import fcntl
import os
import select
import socket
import struct
import threading
import time
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

KEEPALIVE_INTERVAL_SEC = 25.0


def create_tun(dev_name: str) -> int:
    """Создать persistent TUN-интерфейс через ioctl."""
    os.system(f"ip tuntap add mode tun {dev_name} 2>/dev/null")
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", dev_name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


class TunnelPeer:
    """Описание активного peer (одного клиента)."""

    def __init__(self, key_id: str, key_b64: str, allowed_ips: list, tun_ip: str = "10.200.200.2"):
        self.key_id = key_id
        self.key = base64.b64decode(key_b64)
        self.aesgcm = AESGCM(self.key)
        self.allowed_ips = allowed_ips
        self.tun_ip = tun_ip
        self.udp_addr: Optional[tuple] = None
        self.last_seen = 0.0


class TunnelServer:
    """Серверный forwarder: UDP ↔ TUN."""

    def __init__(self, listen_port: int = 51820, tun_dev: str = "tun0", tun_ip: str = "10.200.200.1/24"):
        self.listen_port = listen_port
        self.tun_dev = tun_dev
        self.tun_ip = tun_ip
        self.sock: Optional[socket.socket] = None
        self.tun_fd: Optional[int] = None
        self.peers: Dict[str, TunnelPeer] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Запустить сокет, создать TUN и начать цикл обработки."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.listen_port))
        self.tun_fd = create_tun(self.tun_dev)
        os.system(f"ip addr add {self.tun_ip} dev {self.tun_dev} 2>/dev/null")
        os.system(f"ip link set mtu 1280 dev {self.tun_dev} 2>/dev/null")
        os.system(f"ip link set up dev {self.tun_dev} 2>/dev/null")
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Остановить forwarder и удалить TUN."""
        self._running = False
        if self.sock:
            self.sock.close()
        if self.tun_fd:
            os.close(self.tun_fd)
            os.system(f"ip tuntap del mode tun {self.tun_dev} 2>/dev/null")

    def add_peer(self, key_id: str, key_b64: str, allowed_ips: list, tun_ip: str = "10.200.200.2") -> None:
        """Активировать peer (после валидации билета)."""
        with self._lock:
            self.peers[key_id] = TunnelPeer(key_id, key_b64, allowed_ips, tun_ip)

    def remove_peer(self, key_id: str) -> None:
        """Деактивировать peer (после revoke)."""
        with self._lock:
            self.peers.pop(key_id, None)

    def list_peers(self) -> Dict[str, TunnelPeer]:
        with self._lock:
            return dict(self.peers)

    def _run(self) -> None:
        while self._running:
            try:
                readable, _, _ = select.select([self.sock, self.tun_fd], [], [], 1.0)
            except (ValueError, OSError):
                break
            for fd in readable:
                if fd == self.sock:
                    try:
                        data, addr = self.sock.recvfrom(2048)
                        self._handle_inbound(data, addr)
                    except OSError:
                        pass
                elif fd == self.tun_fd:
                    try:
                        packet = os.read(self.tun_fd, 2048)
                        self._handle_outbound(packet)
                    except OSError:
                        pass

    def _handle_inbound(self, data: bytes, addr: tuple) -> None:
        """Обработка пакета от клиента (UDP → TUN)."""
        if len(data) < 28:  # 12 nonce + 16 tag минимум
            return
        nonce = data[:12]
        ciphertext = data[12:]
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            try:
                plaintext = peer.aesgcm.decrypt(nonce, ciphertext, None)
                peer.udp_addr = addr
                peer.last_seen = time.time()
                os.write(self.tun_fd, plaintext)
                return
            except Exception:
                continue
        # Silent drop: ни один ключ не смог расшифровать

    def _handle_outbound(self, packet: bytes) -> None:
        """Обработка пакета из TUN (TUN → UDP)."""
        if len(packet) < 20:
            return
        dst_ip = socket.inet_ntoa(packet[16:20])
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            if peer.tun_ip == dst_ip and peer.udp_addr:
                nonce = os.urandom(12)
                ciphertext = peer.aesgcm.encrypt(nonce, packet, None)
                try:
                    self.sock.sendto(nonce + ciphertext, peer.udp_addr)
                except OSError:
                    pass
                return
        # Нет peer для этого dst_ip — drop

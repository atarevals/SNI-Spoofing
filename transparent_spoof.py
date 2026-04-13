"""Transparent SNI Spoofer – intercepts ALL outgoing TLS connections.

Used for Warp / Psiphon / Gool modes where Vwarp needs to connect
directly to Cloudflare IPs (both API registration and WireGuard)
and ALL those connections must get a fake ClientHello injected so
DPI can't block them.

Architecture
~~~~~~~~~~~~
  Vwarp → connects directly to Cloudflare IPs on port 443
  ↓
  WinDivert intercepts the TCP handshake
  ↓
  Injects fake ClientHello with wrong seq# (DPI sees clean SNI)
  ↓
  Real ClientHello goes through (DPI already saw the fake one)
  ↓
  Connection succeeds
"""
import os
import random
import socket
import sys
import threading
import time
import logging

from pydivert import WinDivert, Packet
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker

logger = logging.getLogger("transparent_spoof")


class _TrackedConn:
    """Lightweight per-connection state for transparent injection."""
    __slots__ = ("syn_seq", "syn_ack_seq", "fake_scheduled", "fake_sent",
                 "done", "held_packets")

    def __init__(self):
        self.syn_seq: int = -1
        self.syn_ack_seq: int = -1
        self.fake_scheduled: bool = False
        self.fake_sent: bool = False
        self.done: bool = False
        self.held_packets: list = []  # packets held while fake is pending


class TransparentSpoofServer:
    """Transparent DPI-bypass: inject fake ClientHello on every outgoing
    TLS connection without relaying traffic.

    Parameters
    ----------
    fake_sni : str
        The SNI hostname to put in the fake ClientHello.
    """

    def __init__(self, fake_sni: str = "www.speedtest.net"):
        self.fake_sni = fake_sni.encode() if isinstance(fake_sni, str) else fake_sni
        self.interface_ipv4 = get_default_interface_ipv4()

        self._running = False
        self._thread: threading.Thread | None = None
        self._wd: WinDivert | None = None
        self._conns: dict[tuple, _TrackedConn] = {}
        self._lock = threading.Lock()

        self.on_log = None
        self.on_status_change = None

    def _log(self, msg: str):
        logger.info(msg)
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass

    def _make_fake_hello(self) -> bytes:
        return ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), self.fake_sni, os.urandom(32))

    def _send_fake(self, wd: WinDivert, packet: Packet, conn: _TrackedConn):
        """Send fake ClientHello with wrong seq#, then release held packets."""
        time.sleep(random.uniform(0.001, 0.008))
        if conn.done:
            return
        try:
            fake_data = self._make_fake_hello()
            # Clone packet: outbound ACK → fake data with wrong seq
            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(fake_data)
            packet.tcp.payload = fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
            # Wrong seq so the server ignores it, but DPI processes it
            packet.tcp.seq_num = (conn.syn_seq + 1 - len(fake_data)) & 0xffffffff
            wd.send(packet, True)
        except Exception:
            pass
        finally:
            conn.fake_sent = True
            conn.done = True
            # Release held packets (real ClientHello etc.)
            with self._lock:
                held = list(conn.held_packets)
                conn.held_packets.clear()
                self._conns.pop(
                    next((k for k, v in self._conns.items() if v is conn), None),
                    None,
                )
            for p in held:
                try:
                    wd.send(p, False)
                except Exception:
                    pass

    def _process_packet(self, wd: WinDivert, packet: Packet):
        """Inspect a captured packet, track handshakes, inject fakes."""

        if packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port,
                    packet.ip.dst_addr, packet.tcp.dst_port)

            with self._lock:
                conn = self._conns.get(c_id)

            # ── SYN (new outgoing connection) ────────────────────────────
            if (packet.tcp.syn and not packet.tcp.ack and not packet.tcp.rst
                    and not packet.tcp.fin and len(packet.tcp.payload) == 0):
                conn = _TrackedConn()
                conn.syn_seq = packet.tcp.seq_num
                with self._lock:
                    self._conns[c_id] = conn
                wd.send(packet, False)
                return

            # ── Outbound ACK completing 3-way handshake ──────────────────
            if (conn and not conn.fake_scheduled
                    and packet.tcp.ack and not packet.tcp.syn
                    and not packet.tcp.rst and not packet.tcp.fin
                    and len(packet.tcp.payload) == 0
                    and conn.syn_ack_seq != -1):
                wd.send(packet, False)
                conn.fake_scheduled = True
                threading.Thread(
                    target=self._send_fake, args=(wd, packet, conn),
                    daemon=True).start()
                return

            # ── Hold outbound data while fake is being injected ──────────
            if conn and conn.fake_scheduled and not conn.fake_sent:
                with self._lock:
                    conn.held_packets.append(packet)
                return

            # ── Everything else outbound → passthrough ───────────────────
            wd.send(packet, False)
            return

        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port,
                    packet.ip.src_addr, packet.tcp.src_port)

            with self._lock:
                conn = self._conns.get(c_id)

            # ── SYN-ACK ─────────────────────────────────────────────────
            if (conn and packet.tcp.syn and packet.tcp.ack
                    and not packet.tcp.rst and not packet.tcp.fin
                    and len(packet.tcp.payload) == 0):
                conn.syn_ack_seq = packet.tcp.seq_num
                wd.send(packet, False)
                return

            # ── Everything else inbound → passthrough ────────────────────
            wd.send(packet, False)
            return

        # Should never happen
        wd.send(packet, False)

    def _run(self):
        """Main loop – runs in a dedicated thread."""
        if not self.interface_ipv4:
            self._log("Cannot detect network interface")
            return

        # Match ALL outgoing TCP on port 443 from this machine
        w_filter = (
            f"tcp and tcp.DstPort == 443 and ip.SrcAddr == {self.interface_ipv4}"
            f" or tcp and tcp.SrcPort == 443 and ip.DstAddr == {self.interface_ipv4}"
        )

        self._log(f"Transparent spoofer starting (fake SNI: {self.fake_sni.decode()})")
        self._log(f"WinDivert filter: {w_filter}")

        try:
            self._wd = WinDivert(w_filter)
            with self._wd:
                self._running = True
                if self.on_status_change:
                    self.on_status_change(True)
                self._log("Transparent SNI spoofer active – all port-443 traffic is being spoofed")

                while self._running:
                    try:
                        packet = self._wd.recv(65575)
                    except Exception:
                        if not self._running:
                            break
                        raise
                    self._process_packet(self._wd, packet)
        except Exception as exc:
            self._log(f"Transparent spoofer error: {exc}")
        finally:
            self._running = False
            if self.on_status_change:
                self.on_status_change(False)
            self._log("Transparent spoofer stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            self._log("Already running")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._wd:
            try:
                self._wd.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def is_running(self):
        return self._running

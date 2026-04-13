import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import random
import logging

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

logger = logging.getLogger("sni_proxy")


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.join(get_exe_dir(), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)


def save_config(config, config_path=None):
    if config_path is None:
        config_path = os.path.join(get_exe_dir(), 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)


# ---------------------------------------------------------------------------
#  Bidirectional relay – no mutual cancellation, clean socket shutdown
# ---------------------------------------------------------------------------

async def _relay_pair(sock_a: socket.socket, sock_b: socket.socket):
    loop = asyncio.get_running_loop()
    shutdown_initiated = False

    def _shutdown_both():
        nonlocal shutdown_initiated
        if shutdown_initiated:
            return
        shutdown_initiated = True
        for s in (sock_a, sock_b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    async def _forward(src, dst):
        try:
            while True:
                data = await loop.sock_recv(src, 65536)
                if not data:
                    break
                await loop.sock_sendall(dst, data)
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            _shutdown_both()

    await asyncio.gather(
        _forward(sock_a, sock_b),
        _forward(sock_b, sock_a),
        return_exceptions=True,
    )


# ---------------------------------------------------------------------------
#  ProxyServer – importable & controllable from CLI or GUI
# ---------------------------------------------------------------------------

class ProxyServer:
    def __init__(self, config: dict):
        self.config = config
        self.listen_host = config["LISTEN_HOST"]
        self.listen_port = config["LISTEN_PORT"]
        self.fake_sni = config["FAKE_SNI"].encode()
        self.connect_ip = config["CONNECT_IP"]
        self.connect_port = config["CONNECT_PORT"]
        self.interface_ipv4 = get_default_interface_ipv4(self.connect_ip)
        self.data_mode = "tls"
        self.bypass_method = "wrong_seq"
        self.gaming_mode = config.get("gaming_mode", False)

        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server_sock: socket.socket | None = None
        self._fake_connections: dict[tuple, FakeInjectiveConnection] = {}
        self._injector: FakeTcpInjector | None = None
        self._active_connections = 0
        self._total_connections = 0

        # UI callbacks (thread-safe, fire-and-forget)
        self.on_log = None
        self.on_status_change = None
        self.on_connection_count_change = None

    # ---------------------------------------------------------------- helpers

    def _log(self, msg: str, level: str = "info"):
        logger.log(getattr(logging, level.upper(), logging.INFO), msg)
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass

    def _update_conn_count(self, delta: int):
        self._active_connections += delta
        if delta > 0:
            self._total_connections += delta
        if self.on_connection_count_change:
            try:
                self.on_connection_count_change(
                    self._active_connections, self._total_connections)
            except Exception:
                pass

    @staticmethod
    def _configure_sock(sock: socket.socket, gaming: bool = False):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if gaming:
            # Small buffers → lower latency, less queuing
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        else:
            # Large buffers → higher throughput
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)

    # ---------------------------------------------------------------- handler

    async def _handle(self, incoming_sock: socket.socket, addr):
        self._update_conn_count(1)
        outgoing_sock = None
        try:
            loop = asyncio.get_running_loop()

            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), self.fake_sni, os.urandom(32))

            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            outgoing_sock.bind((self.interface_ipv4, 0))
            self._configure_sock(outgoing_sock, self.gaming_mode)

            src_port = outgoing_sock.getsockname()[1]
            fake_conn = FakeInjectiveConnection(
                outgoing_sock, self.interface_ipv4, self.connect_ip,
                src_port, self.connect_port, fake_data,
                self.bypass_method, incoming_sock)
            self._fake_connections[fake_conn.id] = fake_conn

            try:
                await asyncio.wait_for(
                    loop.sock_connect(outgoing_sock,
                                      (self.connect_ip, self.connect_port)),
                    timeout=10)
            except Exception:
                fake_conn.monitor = False
                self._fake_connections.pop(fake_conn.id, None)
                self._log(f"Connect to {self.connect_ip}:{self.connect_port} failed")
                return

            # Random micro-jitter to defeat timing-based DPI fingerprinting
            await asyncio.sleep(random.uniform(0.001, 0.008))

            try:
                await asyncio.wait_for(fake_conn.t2a_event.wait(), 5)
                if fake_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_conn.t2a_msg != "fake_data_ack_recv":
                    self._log(f"Injector error: {fake_conn.t2a_msg}", "error")
                    return
            except (asyncio.TimeoutError, ValueError):
                self._log("Fake handshake failed or timed out")
                return
            finally:
                fake_conn.monitor = False
                self._fake_connections.pop(fake_conn.id, None)

            # Optimize the incoming socket too before relay
            self._configure_sock(incoming_sock, self.gaming_mode)

            # Bidirectional relay – clean shutdown, no recursion
            await _relay_pair(incoming_sock, outgoing_sock)

        except asyncio.CancelledError:
            pass
        except Exception:
            self._log(traceback.format_exc(), "error")
        finally:
            self._update_conn_count(-1)
            for s in (incoming_sock, outgoing_sock):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    # ---------------------------------------------------------------- server

    async def _serve(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setblocking(False)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_host, self.listen_port))
        self._configure_sock(self._server_sock, self.gaming_mode)
        self._server_sock.listen(128)

        loop = asyncio.get_running_loop()
        self._log(f"Listening on {self.listen_host}:{self.listen_port}")
        self._running = True
        if self.on_status_change:
            self.on_status_change(True)

        tasks: set[asyncio.Task] = set()
        try:
            while self._running:
                try:
                    incoming_sock, addr = await asyncio.wait_for(
                        loop.sock_accept(self._server_sock), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                except OSError:
                    if not self._running:
                        break
                    raise
                incoming_sock.setblocking(False)
                task = asyncio.create_task(self._handle(incoming_sock, addr))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
            self._running = False
            if self.on_status_change:
                self.on_status_change(False)

    # ---------------------------------------------------------------- thread

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        w_filter = (
            f"tcp and ((ip.SrcAddr == {self.interface_ipv4}"
            f" and ip.DstAddr == {self.connect_ip})"
            f" or (ip.SrcAddr == {self.connect_ip}"
            f" and ip.DstAddr == {self.interface_ipv4}))")
        self._injector = FakeTcpInjector(w_filter, self._fake_connections)
        threading.Thread(target=self._injector.run, daemon=True).start()
        self._log("Packet injector started")

        try:
            self._loop.run_until_complete(self._serve())
        except Exception:
            self._log(traceback.format_exc(), "error")
        finally:
            self._loop.close()
            self._loop = None

    # ---------------------------------------------------------------- public

    def start(self):
        if self._thread and self._thread.is_alive():
            self._log("Already running")
            return
        if not self.interface_ipv4:
            self._log("Cannot detect network interface. Check connection.", "error")
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._log("Stopping …")
        if self._injector:
            try:
                self._injector.w.close()
            except Exception:
                pass
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._log("Stopped")
        if self.on_status_change:
            self.on_status_change(False)

    @property
    def is_running(self):
        return self._running


# ---------------------------------------------------------------------------
#  CLI entry point (still works standalone)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = load_config()
    server = ProxyServer(cfg)
    server.on_log = lambda m: print(m)

    print("اگر از این برنامه برای دسترسی به اینترنت آزاد استفاده می‌کنید حمایت فراموش نشه")
    print("پروژه‌ها و برنامه‌های زیادی برای دسترسی تمام مردم ایران به اینترنت آزاد در نظر دارم"
          " که به حمایت شما نیاز دارد")
    print("\nUSDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")

    server.start()
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()

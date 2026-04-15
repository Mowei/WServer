"""
Minimal wstunnel HTTP CONNECT proxy client.

Requires: pip install websocket-client
"""

import base64
import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
from urllib.parse import urlparse
import uuid

import websocket


SERVER = ""
PATH_PREFIX = "v1"
LISTEN = ("127.0.0.1", 3456)
VERIFY_TLS = False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal wstunnel HTTP CONNECT proxy client")
    parser.add_argument(
        "-s",
        "--server",
        default=os.getenv("WST_SERVER", SERVER),
        help="wstunnel server URL (env: WST_SERVER)",
    )
    parser.add_argument(
        "-P",
        "--path-prefix",
        default=os.getenv("WST_PATH_PREFIX", PATH_PREFIX),
        help="HTTP upgrade path prefix (env: WST_PATH_PREFIX)",
    )
    parser.add_argument(
        "-l",
        "--listen-ip",
        default=os.getenv("WST_LISTEN_IP", LISTEN[0]),
        help="Local listen IP (env: WST_LISTEN_IP)",
    )
    parser.add_argument(
        "-p",
        "--listen-port",
        type=int,
        default=int(os.getenv("WST_LISTEN_PORT", str(LISTEN[1]))),
        help="Local listen port (env: WST_LISTEN_PORT)",
    )
    parser.add_argument(
        "-k",
        "--verify-tls",
        action="store_true",
        default=_env_bool("WST_VERIFY_TLS", VERIFY_TLS),
        help="Enable TLS certificate verification (env: WST_VERIFY_TLS)",
    )
    return parser.parse_args()


def _apply_args(args: argparse.Namespace) -> None:
    global SERVER, PATH_PREFIX, LISTEN, VERIFY_TLS

    parsed = urlparse(args.server)
    if parsed.scheme not in ("ws", "wss"):
        raise ValueError("--server must use ws:// or wss://")

    SERVER = args.server
    PATH_PREFIX = args.path_prefix
    LISTEN = (args.listen_ip, args.listen_port)
    VERIFY_TLS = args.verify_tls
    print("Effective config:")
    print(f"  server: {SERVER}")
    print(f"  path_prefix: {PATH_PREFIX}")
    print(f"  listen_ip: {LISTEN[0]}")
    print(f"  listen_port: {LISTEN[1]}")
    print(f"  verify_tls: {VERIFY_TLS}")


def _request_id() -> str:
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    return str(uuid.uuid4())


def make_jwt(host: str, port: int) -> str:
    header = _b64(json.dumps({"typ": "JWT", "alg": "HS256"}, separators=(",", ":")).encode())
    payload = _b64(
        json.dumps(
            {
                "id": _request_id(),
                "p": {"Tcp": {"proxy_protocol": False}},
                "r": host,
                "rp": port,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(b"any-secret", signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


def parse_connect_authority(authority: str) -> tuple[str, int]:
    if authority.startswith("["):
        pos = authority.rfind("]:")
        if pos <= 0:
            raise ValueError("invalid IPv6 authority")
        return authority[1:pos], int(authority[pos + 2 :])

    host, sep, port = authority.rpartition(":")
    if not sep:
        raise ValueError("missing port in CONNECT authority")
    return host, int(port)


def read_http_head(sock: socket.socket) -> bytes:
    buf = bytearray()
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def open_wstunnel_ws(host: str, port: int) -> websocket.WebSocket:
    jwt = make_jwt(host, port)
    ws_url = f"{SERVER}/{PATH_PREFIX}/events"
    headers = [f"Sec-WebSocket-Protocol: v1, authorization.bearer.{jwt}"]

    sslopt = {}
    if not VERIFY_TLS:
        sslopt = {
            "cert_reqs": ssl.CERT_NONE,
            "check_hostname": False,
        }

    ws = websocket.create_connection(
        ws_url,
        header=headers,
        sslopt=sslopt,
        timeout=20,
        enable_multithread=True,
    )

    # Upstream expects unmasked payload bytes for data frames.
    ws.set_mask_key(lambda _n: b"\x00\x00\x00\x00")
    return ws


def relay(client: socket.socket, ws: websocket.WebSocket) -> None:
    stop = threading.Event()

    def local_to_ws() -> None:
        try:
            while not stop.is_set():
                data = client.recv(65536)
                if not data:
                    break
                ws.send(data, opcode=websocket.ABNF.OPCODE_BINARY)
        except Exception:
            pass
        finally:
            stop.set()

    def ws_to_local() -> None:
        try:
            while not stop.is_set():
                frame = ws.recv_frame()
                if frame is None:
                    break

                if frame.opcode == websocket.ABNF.OPCODE_BINARY:
                    client.sendall(frame.data)
                elif frame.opcode == websocket.ABNF.OPCODE_TEXT:
                    client.sendall(frame.data.encode())
                elif frame.opcode == websocket.ABNF.OPCODE_PING:
                    ws.pong(frame.data)
                elif frame.opcode == websocket.ABNF.OPCODE_CLOSE:
                    break
        except Exception:
            pass
        finally:
            stop.set()

    t1 = threading.Thread(target=local_to_ws, daemon=True)
    t2 = threading.Thread(target=ws_to_local, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle_client(client: socket.socket, _addr) -> None:
    ws = None
    try:
        head = read_http_head(client)
        if b"\r\n\r\n" not in head:
            return

        first_line = head.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        parts = first_line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        host, port = parse_connect_authority(parts[1])
        ws = open_wstunnel_ws(host, port)

        client.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        relay(client, ws)
    except Exception as e:
        print(f"[tunnel] error: {e}")
    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def main() -> None:
    host, port = LISTEN
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(128)
    print(f"HTTP proxy listening on {host}:{port} -> {SERVER}")

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    finally:
        server.close()


if __name__ == "__main__":
    _apply_args(_parse_args())
    main()

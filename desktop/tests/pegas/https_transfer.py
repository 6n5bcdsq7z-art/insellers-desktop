"""Loopback acceptance of the real Pegas binaries. No production credentials or TUN."""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start(stack, command, cwd):
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop():
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    stack.callback(stop)
    return process


def listening(port, process):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.3):
                return
        except OSError:
            time.sleep(.1)
    raise RuntimeError("loopback listener did not start")


def check(client, endpoint, folder):
    cert = folder / "cert.pem"
    key = folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    password = secrets.token_hex(32)
    payload = os.urandom(1024 * 1024)

    class Site(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    with http.server.HTTPServer(("127.0.0.1", 0), Site) as site, contextlib.ExitStack() as stack:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        site.socket = tls.wrap_socket(site.socket, server_side=True)
        threading.Thread(target=site.serve_forever, daemon=True).start()
        stack.callback(site.shutdown)
        entry = unused_port()
        (folder/"users.toml").write_text('[[client]]\nusername="fixture"\npassword='+json.dumps(password))
        (folder/"vpn.toml").write_text(f'listen_address="127.0.0.1:{entry}"\n'
                                      'credentials_file="users.toml"\nallow_private_network_connections=true\n[listen_protocols.http2]\n')
        (folder/"hosts.toml").write_text('[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
        server = start(stack, [endpoint, "--jobs", "2", "vpn.toml", "hosts.toml"], folder)
        listening(entry, server)
        for valid in (True, False):
            socks = unused_port()
            config = ('loglevel="error"\nvpn_mode="general"\nkillswitch_enabled=false\nexclusions=[]\n'
                      f'[endpoint]\nhostname="localhost"\naddresses=["127.0.0.1:{entry}"]\nusername="fixture"\n'
                      f'password={json.dumps(password if valid else secrets.token_hex(32))}\n'
                      f'skip_verification=false\ncertificate={json.dumps(cert.read_text())}\nupstream_protocol="http2"\n'
                      f'[listener.socks]\naddress="127.0.0.1:{socks}"\n')
            (folder/"client.toml").write_text(config)
            with contextlib.ExitStack() as client_stack:
                client_process = start(client_stack, [client, "-c", "client.toml"], folder)
                if valid:
                    listening(socks, client_process)
                else:
                    # Authentication may fail before the local listener opens.
                    time.sleep(.8)
                for _ in range(2 if valid else 1):
                    result = subprocess.run(["curl", "--fail", "--silent", "--noproxy", "", "--socks5-hostname",
                                             f"127.0.0.1:{socks}", "--cacert", cert, "--max-time", "8",
                                             f"https://127.0.0.1:{site.server_port}/file"], capture_output=True)
                    if valid and (result.returncode or hashlib.sha256(result.stdout).digest() != hashlib.sha256(payload).digest()):
                        raise RuntimeError("authenticated HTTPS transfer failed")
                    if not valid and (result.returncode == 0 or result.stdout):
                        raise RuntimeError("access with invalid password")
            print("2 x 1 MiB HTTPS verified" if valid else "invalid credentials: no data", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("endpoint", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as scratch:
        check(args.client.resolve(), args.endpoint.resolve(), Path(scratch))

"""Verify actual Xray forwards the TLS name when TUN supplies an IP; local fixtures only."""
import argparse
from pathlib import Path
import json
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--xray', required=True)
p.add_argument('--emit', required=True)
a = p.parse_args()

def listener():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); s.settimeout(6)
    return s

def exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n-len(data))
        if not chunk: raise EOFError()
        data += chunk
    return data

with tempfile.TemporaryDirectory(prefix='insellers-tls-name-') as directory:
    root = Path(directory)
    cert, key = root/'cert.pem', root/'key.pem'
    config = root/'cert.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=fixture.test\n[ext]\nsubjectAltName=DNS:fixture.test\nbasicConstraints=critical,CA:TRUE\n', encoding='utf-8')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)], capture_output=True, check=True, timeout=15)
    key.chmod(0o600)
    tls, upstream = listener(), listener()
    tls_port, inner_port = tls.getsockname()[1], upstream.getsockname()[1]
    observed = []
    def server():
        try:
            with tls.accept()[0] as s:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
                with ctx.wrap_socket(s, server_side=True) as c:
                    c.settimeout(4); c.recv(8192)
                    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nname-restored-ok!\n')
        except (OSError, ssl.SSLError): pass
    def proxy():
        try:
            with upstream.accept()[0] as c:
                c.settimeout(4)
                version, n = exact(c, 2); exact(c, n); c.sendall(b'\x05\x00')
                version, command, reserved, kind = exact(c, 4)
                host = exact(c, exact(c, 1)[0]).decode() if kind == 3 else exact(c, 4 if kind == 1 else 16)
                port = struct.unpack('!H', exact(c, 2))[0]
                observed.append('tls_name' if kind == 3 and host == 'fixture.test' else 'numeric_address')
                if observed[-1] != 'tls_name':
                    c.sendall(b'\x05\x04\x00\x01'+b'\x00'*6); return
                assert port == tls_port
                with socket.create_connection(('127.0.0.1', tls_port), timeout=3) as target:
                    c.sendall(b'\x05\x00\x00\x01'+b'\x00'*6)
                    deadline = time.monotonic()+6
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([c, target], [], [], .2)
                        for source in ready:
                            data = source.recv(65536)
                            if not data: return
                            (target if source is c else c).sendall(data)
        except (OSError, EOFError): pass
    for task in (server, proxy): threading.Thread(target=task, daemon=True).start()
    profile = {'protocol':'naive','server':'fixture.insellers.su','server_port':26443,'username':'n_'+'a'*64,'password':'b'*64,'expires_ms':int(time.time()*1000)+60000,'dns':{'url':'https://fixture.insellers.su/dns-query','host':'fixture.insellers.su','ip':'127.0.0.1'}}
    fixture = root/'profile.json'; fixture.write_text(json.dumps(profile), encoding='utf-8'); fixture.chmod(0o600)
    subprocess.run([a.emit,str(fixture),str(root),str(inner_port)], check=True, capture_output=True)
    route = json.loads((root/'router.json').read_text(encoding='utf-8'))
    ports = []
    for inbound in route['inbounds']:
        s = listener(); ports.append(s.getsockname()[1]); s.close(); inbound['port'] = ports[-1]
    route['outbounds'][0]['settings']['servers'][0]['port'] = inner_port
    router = root/'router.json'; router.write_text(json.dumps(route), encoding='utf-8'); router.chmod(0o600)
    core = subprocess.Popen([a.xray,'run','-c',str(router)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for attempt in range(100):
            if core.poll() is not None: raise RuntimeError('Xray startup failed')
            try:
                with socket.create_connection(('127.0.0.1', ports[0]), timeout=.05): break
            except OSError: time.sleep(.03)
        r = subprocess.run(['curl','--silent','--show-error','--noproxy','','--proxy','socks5://127.0.0.1:'+str(ports[0]),'--resolve','fixture.test:'+str(tls_port)+':127.0.0.1','--cacert',str(cert),'--connect-timeout','3','--max-time','6','https://fixture.test:'+str(tls_port)+'/'],capture_output=True,timeout=8)
        ok = r.returncode == 0 and r.stdout == b'name-restored-ok!\n' and observed == ['tls_name']
        print(json.dumps({'actual_xray_tls_name_restored':ok,'upstream_address_kind':observed,'https_certificate_verified':r.returncode == 0,'fixtures':'loopback only; no user credentials'}))
        assert ok, 'TUN IP must reach the upstream proxy as its verified TLS name'
    finally:
        core.terminate()
        try: core.wait(timeout=3)
        except subprocess.TimeoutExpired: core.kill(); core.wait()
        tls.close(); upstream.close()

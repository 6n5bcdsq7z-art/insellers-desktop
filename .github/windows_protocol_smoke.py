"""Windows real processes; TUIC/AnyTLS HTTPS fixture, not system TUN acceptance."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'ops/deploy'))
import windows_bundle


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]


def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)


def ready(p, n):
    until=time.monotonic()+12
    while time.monotonic()<until:
        if p.poll() is not None: raise RuntimeError('engine exited before SOCKS readiness')
        try:
            with socket.create_connection(('127.0.0.1',n),timeout=.3) as s:
                s.sendall(b'\x05\x01\x00');s.settimeout(1)
                if s.recv(2)==b'\x05\x00': return
        except OSError: pass
        time.sleep(.1)
    raise RuntimeError('SOCKS startup timeout')


def write(p, value):
    p.write_text(json.dumps(value)); return str(p)


def run(a):
    results={}
    print("fixture: verify pinned engine archives",flush=True)
    with tempfile.TemporaryDirectory(prefix='ins-windows-protocols-') as td:
        root=Path(td)
        for item in json.loads(windows_bundle.MANIFEST.read_text()):
            for name, kind, data in windows_bundle.payloads(item,a.archives):
                if kind in ('exe','dll'): (root/name).write_bytes(data)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        content=os.urandom(1024*1024);(root/'payload').write_bytes(content)
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self,*args): pass
        origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=td))
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
        origin.socket=ctx.wrap_socket(origin.socket,server_side=True)
        threading.Thread(target=origin.serve_forever,daemon=True).start()
        try:
            for kind in ('naive','tuic','mieru','anytls'):
                print('fixture: '+kind+' startup',flush=True)
                folder=root/kind;folder.mkdir();local,remote=port(),port()
                profile={'protocol':kind,'server':'r1.insellers.su','server_port':remote,'username':('m_'+'a'*62) if kind=='mieru' else ('n_'+'a'*64),'password':'b'*64,'uuid':'00000000-0000-4000-8000-000000000001','expires_ms':int(time.time()*1000)+300000,'dns':{'url':'https://vpn.insellers.su/dns-query/fixture','host':'vpn.insellers.su','ip':'89.110.97.227'}}
                subprocess.run([str(a.emit),write(folder/'profile.json',profile),str(folder),str(local)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                config=json.loads((folder/'engine.json').read_text());server=None;client=None
                try:
                    if kind in ('tuic','anytls'):
                        out=config['outbounds'][0];out['server']='127.0.0.1';out['tls'].update(server_name='localhost',certificate_path=str(root/'cert.pem'))
                        inbound={'type':kind,'listen':'127.0.0.1','listen_port':remote,'users':[{'password':profile['password'],**({'uuid':profile['uuid']} if kind=='tuic' else {'name':profile['username']})}],'tls':{'enabled':True,'certificate_path':str(root/'cert.pem'),'key_path':str(root/'key.pem')}}
                        if kind=='tuic': inbound['tls']['alpn']=['h3']
                        sc={'log':{'level':'error'},'inbounds':[inbound],'outbounds':[{'type':'direct'}]}
                        server=subprocess.Popen([str(root/'tuic.exe'),'run','-c',write(folder/'server.json',sc)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    elif kind=='naive':
                        config['proxy']=f"https://{profile['username']}:{profile['password']}@localhost:{remote}"
                    else:
                        config['profiles'][0]['servers'][0]['domainName']='localhost'
                    path=write(folder/'engine.json',config);env=dict(os.environ)
                    exe=root/('tuic.exe' if kind=='anytls' else kind+'.exe')
                    args=[str(exe),path] if kind=='naive' else [str(exe),'run','-c',path]
                    if kind=='mieru': args=[str(exe),'run'];env['MIERU_CONFIG_JSON_FILE']=path
                    client=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);ready(client,local)
                    result={'real_process_and_socks':True,'https_verified':False,'os_tun_verified':False}
                    if server:
                        print('fixture: '+kind+' HTTPS with valid credentials',flush=True)
                        def fetch():
                            dest=folder/'download'
                            r=subprocess.run(['curl','-fsS','--proto','=https','--cacert',str(root/'cert.pem'),'--socks5-hostname',f'127.0.0.1:{local}','--noproxy','','--max-time','15','-o',str(dest),f'https://127.0.0.1:{origin.server_port}/payload'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                            return r.returncode==0 and dest.read_bytes()==content
                        # A listening client can precede its server's initial bind.
                        deadline=time.monotonic()+20
                        while not fetch():
                            if time.monotonic()>deadline: raise RuntimeError('HTTPS fixture failed')
                            time.sleep(.2)
                        for _ in range(2):
                            if not fetch(): raise RuntimeError('Repeated HTTPS failed')
                        result.update(https_verified=True,requests=3,bytes_each=len(content))
                        print('fixture: '+kind+' reject wrong credentials',flush=True)
                        stop(client);config['outbounds'][0]['password']='c'*64;write(folder/'engine.json',config)
                        client=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);ready(client,local)
                        if fetch(): raise RuntimeError('Invalid credentials accepted')
                        result['invalid_password_rejected']=True
                    stop(client)
                    with socket.socket() as check:
                        check.settimeout(.5)
                        if check.connect_ex(('127.0.0.1',local))==0: raise RuntimeError('Stopped process retained SOCKS listener')
                    result['stop_closes_listener']=True;results[kind]=result
                finally: stop(client);stop(server)
        finally: origin.shutdown();origin.server_close()
    return {'scope':'Windows isolated fixture; no production, OS TUN or Russian network claim','results':results}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--archives',type=Path,required=True);p.add_argument('--emit',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        result=run(a);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    except Exception as e:
        print('Windows fixture failed: '+type(e).__name__);raise SystemExit(1)

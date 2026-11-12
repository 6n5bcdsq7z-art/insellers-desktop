"""Verify real SOCKS UDP capability replies; no VPN or external packets are sent.
Usage: python3 udp-capability-wire.py VERIFIED_XRAY EMIT_PROTOCOL_PROFILE
"""
import json,os,pathlib,socket,struct,subprocess,sys,tempfile,time
xray,emitter=sys.argv[1:]
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def read(s,n):
 data=b''
 while len(data)<n:
  part=s.recv(n-len(data))
  if not part:raise EOFError()
  data+=part
 return data
for kind,supported in [('naive',False),('anytls',False),('tuic',True),('mieru',True)]:
 with tempfile.TemporaryDirectory(prefix='native-udp-contract-') as td:
  root=pathlib.Path(td);root.chmod(0o700);profile={'protocol':kind,'server':'r1.insellers.su','server_port':26446,'username':('m_'+'a'*62 if kind=='mieru' else 'n_'+'a'*64),'password':'b'*64,'uuid':'00000000-0000-4000-8000-000000000001','expires_ms':int(time.time()*1000)+60000,'dns':{'url':'https://vpn.insellers.su/dns-query/fixture','host':'vpn.insellers.su','ip':'89.110.97.227'}}
  p=root/'profile.json';p.write_text(json.dumps(profile));p.chmod(0o600);subprocess.run([emitter,str(p),str(root),str(port())],check=True,stdout=subprocess.DEVNULL)
  p=root/'router.json';cfg=json.loads(p.read_text());listen=port()
  for i in cfg['inbounds']:i['port']=listen if i['tag']=='socks-in' else port()
  p.write_text(json.dumps(cfg));p.chmod(0o600);child=subprocess.Popen([xray,'run','-c',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   for _ in range(40):
    try:s=socket.create_connection(('127.0.0.1',listen),.1);break
    except OSError:time.sleep(.025)
   else:raise RuntimeError('test SOCKS did not start')
   with s:
    s.settimeout(1);s.sendall(b'\5\1\0');assert read(s,2)==b'\5\0';began=time.monotonic();s.sendall(b'\5\3\0\1'+bytes(6));reply=read(s,4);ms=round((time.monotonic()-began)*1000)
    assert reply[0]==5 and (reply[1]==0)==supported,(kind,reply[1]);assert ms<1000
   print(json.dumps({'protocol':kind,'udp_association_accepted':reply[1]==0,'expected':supported,'reply_code':reply[1],'ms':ms}),flush=True)
  finally:
   child.terminate()
   try:child.wait(timeout=2)
   except subprocess.TimeoutExpired:child.kill();child.wait()
print('4 real SOCKS capability cases PASS; system VPN unchanged')

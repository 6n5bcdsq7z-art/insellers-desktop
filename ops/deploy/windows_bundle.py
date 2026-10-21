"""Stage pinned official Windows x64 engines and their adjacent dependencies."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import extra_bundle

MANIFEST = Path(__file__).with_name('windows-protocol-assets.json')


def inspect_pe(data, dll=False):
    if len(data) < 64 or data[:2] != b'MZ': raise ValueError('Not PE')
    offset = struct.unpack_from('<I', data, 60)[0]
    if offset + 80 > len(data) or data[offset:offset+4] != b'PE\0\0': raise ValueError('Invalid PE')
    machine = struct.unpack_from('<H', data, offset+4)[0]
    flags = struct.unpack_from('<H', data, offset+22)[0]
    magic = struct.unpack_from('<H', data, offset+24)[0]
    if machine != 0x8664 or magic != 0x20b or bool(flags & 0x2000) != dll:
        raise ValueError('Not the required Windows x64 executable/library')


def payloads(item, cache):
    raw = (cache / item['name']).read_bytes()
    if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise ValueError('Archive checksum mismatch')
    out = []
    with zipfile.ZipFile(cache / item['name']) as z:
        for member in [{'member':item['member'],'sha256':item['binary_sha256'],'destination':item['protocol']+'.exe','kind':'exe'}, *item.get('dependencies',[])]:
            infos = [i for i in z.infolist() if i.filename == member['member']]
            if len(infos) != 1 or infos[0].is_dir(): raise ValueError('Missing/duplicate archive member')
            data = z.read(infos[0])
            if hashlib.sha256(data).hexdigest() != member['sha256']: raise ValueError('Payload checksum mismatch')
            if member['kind'] in ('exe','dll'): inspect_pe(data, member['kind']=='dll')
            out.append((member['destination'], member['kind'], data))
    return out


def stage(desktop, cache, output):
    target = 'x86_64-pc-windows-msvc'
    base = desktop / 'src-tauri'
    items = json.loads(MANIFEST.read_text())
    verified = [(i, payloads(i, cache)) for i in items]
    bundle = json.loads((base / 'tauri.conf.json').read_text())['bundle']
    bins = list(bundle['externalBin'])
    resources = bundle.get('resources', [])
    resources = dict(resources) if isinstance(resources, dict) else {p:p for p in resources}
    for item, payload in verified:
        kind = item['protocol']
        for name, typ, data in payload:
            if typ == 'exe':
                extra_bundle.put(base/'binaries'/(kind+'-'+target+'.exe'), data)
                bins.append('binaries/'+kind)
            else:
                path = 'resources/protocols/'+name
                extra_bundle.put(base/path, data, 0o644)
                resources[path] = name if typ == 'dll' else path
        license_data = extra_bundle.license_data(kind) if kind != 'naive' else MANIFEST.with_name('naive.LICENSE').read_bytes()
        path = 'resources/'+kind+'.LICENSE'
        extra_bundle.put(base/path, license_data, 0o644); resources[path] = path
    path = 'resources/GPL-3.0.txt'
    extra_bundle.put(base/path, extra_bundle.license_data('mieru'), 0o644); resources[path] = path
    path = 'resources/protocol-sources.txt'
    sources = ('Unmodified upstream engines; corresponding source and releases:\n'
               'https://github.com/klzgrad/naiveproxy/tree/v154.0.8037.49-4\n'
               'https://github.com/SagerNet/sing-box/tree/v1.14.3\n'
               'https://github.com/enfein/mieru/tree/v3.38.1\n'
               'See the accompanying license files.\n')
    extra_bundle.put(base/path, sources.encode(), 0o644); resources[path] = path
    output.mkdir(parents=True, exist_ok=False)
    overlay = output/'protocols.tauri.json'
    overlay.write_text(json.dumps({'bundle':{'externalBin':list(dict.fromkeys(bins)),'resources':resources}},indent=2)+'\n')
    (output/'receipt.json').write_text(json.dumps({'target':target,'protocols':['naive','tuic','mieru','anytls'],'signed':False,'device_tested':False},indent=2)+'\n')
    return overlay

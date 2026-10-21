#!/usr/bin/env python3
"""Stage pinned real engines. No signing, publication, or unsupported ABI payloads."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import naive_bundle

MANIFEST = Path(__file__).with_name('extra-protocol-assets.json')
LICENSES = {'tuic': ('sing-box.LICENSE', '650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c'),
            'mieru': ('mieru.LICENSE', '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986')}
# TUIC arm64 uses the pinned 16 KiB source build; Mieru has no official armv7 release.
ANDROID = [('tuic','android-arm64','arm64-v8a'), ('tuic','android-armv7','armeabi-v7a'), ('mieru','android-arm64','arm64-v8a')]


def asset(kind, platform, role='client'):
    return next(a for a in json.loads(MANIFEST.read_text())
                if (a['protocol'], a['platform'], a['role']) == (kind, platform, role))


def payload(item, archives):
    raw = (archives / item['name']).read_bytes()
    if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise ValueError('Archive differs from pinned upstream release')
    with tarfile.open(archives / item['name']) as archive:
        members = [m for m in archive.getmembers() if m.name == item['member']]
        if len(members) != 1 or not members[0].isfile(): raise ValueError('Invalid archive member')
        data = archive.extractfile(members[0]).read()
    if hashlib.sha256(data).hexdigest() != item['binary_sha256']: raise ValueError('Binary checksum mismatch')
    if item['platform'] == 'linux-x64':
        if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH',data,16) not in ((2,62),(3,62)):
            raise ValueError('Not Linux x86-64 executable')
    elif naive_bundle.inspect_binary(data,item['platform'],item['machine']) != item['inspection']:
        raise ValueError('Compatibility inspection changed')
    return data


def put(path, data, mode=0o755):
    if path.is_symlink() or (path.exists() and path.read_bytes() != data):
        raise ValueError('Existing different file preserved: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    if not path.exists():
        with path.open('xb') as f: f.write(data)
    path.chmod(mode)


def license_data(kind):
    name, sha=LICENSES[kind]; data=MANIFEST.with_name(name).read_bytes()
    if hashlib.sha256(data).hexdigest() != sha: raise ValueError('License changed')
    return data


def android(app, archives, verify=False):
    prepared=[]; expected={}
    for kind,platform,abi in ANDROID:
        item=asset(kind,platform); dest=app/'src/main/jniLibs'/abi/('lib'+kind+'.so')
        expected[str(dest.relative_to(app))]=item['binary_sha256']
        if not verify: prepared.append((dest,payload(item,archives)))
    if verify:
        for path,sha in expected.items():
            binary=app/path
            if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest()!=sha: raise ValueError('Engine mismatch')
        for kind in LICENSES:
            for p in (app/'src/main/jniLibs').glob('*/lib'+kind+'.so'):
                if str(p.relative_to(app)) not in expected: raise ValueError('Unapproved ABI engine')
            if (app/'src/main/assets/licenses'/(kind+'.LICENSE')).read_bytes()!=license_data(kind):
                raise ValueError('Missing or changed engine license')
        return
    for dest,data in prepared: put(dest,data)
    for k in LICENSES: put(app/'src/main/assets/licenses'/(k+'.LICENSE'),license_data(k),0o644)
    put(app/'src/main/assets/licenses/GPL-3.0.txt',license_data('mieru'),0o644)


def desktop(base, archives, target, output, overlay=None):
    if output.exists(): raise ValueError('Preserve previous output')
    platforms={'universal-apple-darwin':['mac-arm64','mac-x64'],'aarch64-apple-darwin':['mac-arm64'],
               'x86_64-apple-darwin':['mac-x64'],'x86_64-unknown-linux-gnu':['linux-x64']}[target]
    bundle=json.loads((overlay or base/'tauri.conf.json').read_text())['bundle']
    bins=list(bundle['externalBin']);resources=list(bundle.get('resources',[]))
    with tempfile.TemporaryDirectory(prefix='extra-engines-') as td:
        for kind in LICENSES:
            files=[]
            for platform in platforms:
                file=Path(td)/(kind+platform);put(file,payload(asset(kind,platform),archives));files.append(file)
            binary=files[0]
            if len(files)==2:
                binary=Path(td)/kind
                subprocess.run(['lipo','-create','-output',str(binary),*[str(f) for f in files]],check=True)
                subprocess.run(['lipo',str(binary),'-verify_arch','arm64','x86_64'],check=True)
            put(base/'binaries'/(kind+'-'+target),binary.read_bytes())
            put(base/'resources'/(kind+'.LICENSE'),license_data(kind),0o644)
            bins.append('binaries/'+kind);resources.append('resources/'+kind+'.LICENSE')
    put(base/'resources/GPL-3.0.txt',license_data('mieru'),0o644);resources.append('resources/GPL-3.0.txt')
    output.mkdir(parents=True)
    (output/'protocols.tauri.json').write_text(json.dumps({'bundle':{'externalBin':list(dict.fromkeys(bins)), 'resources':list(dict.fromkeys(resources))}},indent=2)+'\n')
    (output/'receipt.json').write_text(json.dumps({'target':target,'app_minimum_macos':'11.0','engine_minimum_macos':{'tuic':'26.0','mieru':'12.0'},'signed':False},indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archives',type=Path);p.add_argument('--android',type=Path);p.add_argument('--verify',action='store_true')
    p.add_argument('--desktop',type=Path);p.add_argument('--target');p.add_argument('--output',type=Path);p.add_argument('--base-overlay',type=Path)
    a=p.parse_args()
    if a.android: android(a.android,a.archives,a.verify)
    elif a.desktop and a.output: desktop(a.desktop/'src-tauri',a.archives,a.target,a.output,a.base_overlay)
    else: p.error('Specify --android, or --desktop with --target and --output')
    print('Verified engines staged/checked; no signed installer or production claim.')

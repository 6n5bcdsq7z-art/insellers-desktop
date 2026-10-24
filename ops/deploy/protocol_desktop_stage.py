#!/usr/bin/env python3
"""Fetch checksum-pinned engines and compose the candidate Tauri bundle overlay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import traceback
import urllib.request
import extra_bundle
import naive_bundle
import windows_bundle


def download(item,cache):
    path=cache/item['name']
    if path.exists(): data=path.read_bytes()
    else:
        with urllib.request.urlopen(item['url'],timeout=60) as r: data=r.read()
    if len(data)!=item['bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:
        raise ValueError('Upstream archive checksum mismatch')
    if not path.exists():
        with path.open('xb') as f: f.write(data)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--desktop',type=Path,required=True)
    p.add_argument('--target',choices=('universal-apple-darwin','x86_64-unknown-linux-gnu','x86_64-pc-windows-msvc'),required=True)
    p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.cache.mkdir(parents=True,exist_ok=True)
    if a.target == 'x86_64-pc-windows-msvc':
        for item in json.loads(windows_bundle.MANIFEST.read_text()):
            print('Verifying Windows archive: '+item['name'],flush=True)
            download(item,a.cache)
        print(windows_bundle.stage(a.desktop,a.cache,a.output/'all'))
        return
    platforms=['mac-arm64','mac-x64'] if a.target.startswith('universal') else ['linux-x64']
    for item in json.loads(naive_bundle.MANIFEST.read_text())['assets']:
        if item['platform'] in platforms: download(item,a.cache)
    for item in json.loads(extra_bundle.MANIFEST.read_text()):
        if item['platform'] in platforms and item['role']=='client': download(item,a.cache)
    subprocess.run([sys.executable,str(Path(__file__).with_name('naive_desktop_bundle.py')),'--desktop',str(a.desktop),'--archives',str(a.cache),'--target',a.target,'--output',str(a.output/'naive')],check=True)
    extra_bundle.desktop(a.desktop/'src-tauri',a.cache,a.target,a.output/'all',a.output/'naive/naive.tauri.json')
    notices='Unmodified upstream engines; corresponding source and releases:\nhttps://github.com/klzgrad/naiveproxy/tree/v154.0.8037.49-4\nhttps://github.com/SagerNet/sing-box/tree/v1.14.3\nhttps://github.com/enfein/mieru/tree/v3.38.1\nSee the accompanying license files.\n'
    extra_bundle.put(a.desktop/'src-tauri/resources/protocol-sources.txt',notices.encode(),0o644)
    overlay=a.output/'all/protocols.tauri.json';config=json.loads(overlay.read_text())
    config['bundle']['resources'].append('resources/protocol-sources.txt');overlay.write_text(json.dumps(config,indent=2)+'\n')
    print(str(overlay.resolve()))


if __name__=='__main__':
    try: main()
    except Exception as error:
        # Public upstream assets only; never dump runner environment or headers.
        frames = traceback.extract_tb(error.__traceback__)
        location = Path(frames[-1].filename).name + ':' + str(frames[-1].lineno)
        detail = str(error) if isinstance(error, (ValueError, FileNotFoundError, urllib.error.HTTPError)) else type(error).__name__
        detail = (location + ' ' + detail)[:500].replace('%','%25').replace('\n','%0A').replace('\r','%0D')
        print('::error title=Protocol bundle::'+detail,flush=True)
        raise SystemExit(1)

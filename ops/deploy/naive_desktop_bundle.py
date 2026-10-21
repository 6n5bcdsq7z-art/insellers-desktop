#!/usr/bin/env python3
"""Stage pinned desktop Naive and produce a Tauri overlay; no signing/publication.

Use --config <output>/naive.tauri.json in the existing candidate build. The
macOS app retains its macOS 11 minimum; runtime capability requires macOS 13.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import naive_bundle


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--desktop', type=Path, required=True)
    p.add_argument('--archives', type=Path, required=True)
    p.add_argument('--target', choices=('universal-apple-darwin', 'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-unknown-linux-gnu'), required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists(): raise ValueError('Preserve existing overlay/output')
    base = args.desktop / 'src-tauri'
    dest = base / 'binaries' / ('naive-' + args.target)
    if dest.exists() or dest.is_symlink(): raise ValueError('Preserve existing engine')
    platforms = {'universal-apple-darwin': ['mac-arm64', 'mac-x64'],
                 'aarch64-apple-darwin': ['mac-arm64'], 'x86_64-apple-darwin': ['mac-x64'],
                 'x86_64-unknown-linux-gnu': ['linux-x64']}[args.target]
    manifest = json.loads(naive_bundle.MANIFEST.read_text())
    with tempfile.TemporaryDirectory(prefix='naive-desktop-') as td:
        root = Path(td)
        receipts = []
        for platform in platforms:
            asset = next(a for a in manifest['assets'] if a['platform'] == platform)
            receipts.append(naive_bundle.stage(platform, args.archives / asset['name'], root / platform, minimum_macos=(13, 0, 0)))
        binary = root / platforms[0] / 'naive'
        if len(platforms) == 2:
            binary = root / 'naive-universal'
            subprocess.run(['lipo', '-create', '-output', str(binary), *[str(root / name / 'naive') for name in platforms]], check=True)
            subprocess.run(['lipo', str(binary), '-verify_arch', 'arm64', 'x86_64'], check=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, dest)
        dest.chmod(0o755)
    license_file = base / 'resources' / 'naive.LICENSE'
    license_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(naive_bundle.MANIFEST.with_name('naive.LICENSE'), license_file)
    config = json.loads((base / 'tauri.conf.json').read_text())
    bins = list(config['bundle']['externalBin']) + ['binaries/naive']
    # Paths resolve against src-tauri, as with the existing bundle configuration.
    resources = config['bundle'].get('resources', [])
    if not isinstance(resources, list): raise ValueError('Review resource mapping before bundling')
    args.output.mkdir(parents=True)
    (args.output / 'naive.tauri.json').write_text(json.dumps({'bundle': {'externalBin': bins, 'resources': resources + ['resources/naive.LICENSE']}}, indent=2) + '\n')
    (args.output / 'receipt.json').write_text(json.dumps({'target': args.target, 'bundles': receipts, 'app_minimum_macos': '11.0', 'naive_minimum_macos': '13.0', 'signed': False}, indent=2) + '\n')
    print('Engine and license staged; use overlay in the existing signed candidate build.')


if __name__ == '__main__': main()

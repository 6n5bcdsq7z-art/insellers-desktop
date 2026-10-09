"""Build public updater metadata from the exact ZIPs signed by the existing VPN release key."""
import hashlib
import json
import os
from pathlib import Path
import sys

folder = Path(sys.argv[1])
version = '1.0.' + os.environ['GITHUB_RUN_NUMBER']
tag = f"market-{os.environ['GITHUB_RUN_NUMBER']}-{os.environ['GITHUB_SHA'][:7]}"
files = {}
for arch in ('arm64', 'x64'):
    archive = folder / f'INSELLERS-{version}-mac-{arch}.zip'
    signature = archive.with_suffix(archive.suffix + '.sig').read_text().strip()
    files[arch] = {'url': f'https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/download/{tag}/{archive.name}',
                   'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'size': archive.stat().st_size,
                   'signature': signature}
(folder / 'latest-mac-signed.json').write_text(json.dumps({'version': version, 'files': files}, indent=2) + '\n')

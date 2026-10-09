"""Publish only the APK's measured hash, version and signing certificate; no signing secrets."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

apk = Path(sys.argv[1])
sdk = Path(os.environ['ANDROID_HOME']) / 'build-tools' / '35.0.0'
certificate = subprocess.check_output([str(sdk / 'apksigner'), 'verify', '--print-certs', str(apk)], text=True)
match = re.search(r'Signer #1 certificate SHA-256 digest: ([a-f0-9]{64})', certificate)
if not match:
    raise SystemExit('APK signing certificate unavailable')
badging = subprocess.check_output([str(sdk / 'aapt'), 'dump', 'badging', str(apk)], text=True)
version = re.search(r"versionCode='(\d+)' versionName='([^']+)'", badging)
if not version:
    raise SystemExit('APK version unavailable')
tag = f"market-{os.environ['GITHUB_RUN_NUMBER']}-{os.environ['GITHUB_SHA'][:7]}"
feed = {'versionCode': int(version[1]), 'version': version[2],
        'url': f'https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/download/{tag}/{apk.name}',
        'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(), 'certificate_sha256': match[1]}
(apk.parent / 'latest-android.json').write_text(json.dumps(feed, indent=2) + '\n')

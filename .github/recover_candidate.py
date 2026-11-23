"""Restore the immutable files of an existing desktop build, only in the candidate channel."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def api(path, body=None):
    args = ['gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/' + path]
    if body is not None:
        args.extend(['-X', 'PUT', '--input', '-'])
    return json.loads(subprocess.check_output(args, input=json.dumps(body).encode() if body is not None else None))


def validate():
    value = os.environ['BUILD_RUN']
    if not re.fullmatch('[1-9][0-9]{0,19}', value):
        raise ValueError('Invalid run ID')
    run = api('actions/runs/' + value)
    manual_main = run['event'] == 'workflow_dispatch' and run['head_branch'] == 'main'
    release_tag = (run['event'] == 'push'
                   and re.fullmatch(r'desktop-(?:v[0-9]{8}-[0-9]{6}|release-[A-Za-z0-9._-]+)',
                                    run['head_branch'] or '') is not None)
    if (run['path'] != '.github/workflows/desktop.yml'
            or not (manual_main or release_tag)
            or run['status'] != 'completed'
            or run['head_repository']['full_name'] != os.environ['GITHUB_REPOSITORY']):
        raise ValueError('Expected a completed original main or release-tag workflow')
    jobs = api('actions/runs/' + value + '/jobs?per_page=100')['jobs']
    builds = [j for j in jobs if j['name'].startswith('build (')]
    if len(builds) != 3 or any(j['conclusion'] != 'success' for j in builds):
        raise ValueError('All three original builds must have passed')
    entry = api('contents/builds/by-run/' + value + '.json?ref=ci-logs')
    identity = json.loads(base64.b64decode(entry['content']))
    version = identity['version']
    if (not re.fullmatch(r'1\.0\.[0-9]{1,6}', version) or
            identity != dict(version=version, source_commit=run['head_sha'], build_run=int(value))):
        raise ValueError('Build identity mismatch')
    reserved = api('contents/candidates/reserved-' + version + '.json?ref=ci-logs')
    if json.loads(base64.b64decode(reserved['content'])) != identity:
        raise ValueError('Reservation mismatch')
    return identity


def verify(file, signature, public_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    packet = base64.b64decode(signature, validate=True).decode().splitlines()
    raw = base64.b64decode(packet[1], validate=True)
    if len(raw) != 74 or raw[:2] != b'ED' or raw[2:10] != public_key[2:10] or not packet[2].startswith('trusted comment: '):
        raise ValueError('Invalid updater signature format or key')
    key = Ed25519PublicKey.from_public_bytes(public_key[10:])
    with file.open('rb') as stream:
        key.verify(raw[10:], hashlib.file_digest(stream, 'blake2b').digest())
    key.verify(base64.b64decode(packet[3], validate=True), raw[10:] + packet[2].removeprefix('trusted comment: ').encode())


def single(pattern):
    files = list(Path('artifacts').glob('bundle-*/' + pattern))
    if len(files) != 1 or files[0].is_symlink() or files[0].stat().st_size == 0:
        raise ValueError('Missing or ambiguous ' + pattern)
    return files[0]


def matches(url, local):
    with tempfile.TemporaryDirectory() as tmp:
        remote = Path(tmp) / 'response'
        code = subprocess.check_output(['curl', '-sS', '--max-time', '210', '-w', '%{http_code}',
                                        '-o', remote, url], text=True)
        if code == '404':
            return False
        if code != '200':
            raise RuntimeError('Download returned HTTP ' + code)
        with local.open('rb') as expected, remote.open('rb') as actual:
            if hashlib.file_digest(expected, 'sha256').digest() != hashlib.file_digest(actual, 'sha256').digest():
                raise RuntimeError('Existing version differs from original CI artifact')
    return True


def restore(identity):
    version = identity['version']
    base = 'https://vpn.insellers.su/app/desktop/v/' + version + '/'
    updater = json.loads(Path('desktop/src-tauri/tauri.conf.json').read_text())['plugins']['updater']
    key = base64.b64decode(base64.b64decode(updater['pubkey']).decode().splitlines()[1], validate=True)
    platforms = {}
    files = []
    for platform, pattern, name in [
            ('linux-x86_64', '*.AppImage', 'INSELLERS-VPN.AppImage'),
            ('windows-x86_64', '*-setup.exe', 'INSELLERS-VPN-setup.exe'),
            ('darwin-aarch64', '*.app.tar.gz', 'INSELLERS-VPN-mac.app.tar.gz')]:
        file = single(pattern)
        signature = single(pattern + '.sig').read_text().strip()
        verify(file, signature, key)
        platforms[platform] = dict(signature=signature, url=base + name)
        files.append((file, name))
    platforms['darwin-x86_64'] = platforms['darwin-aarch64']
    files.extend((single(pattern), name) for pattern, name in [
        ('*.dmg', 'INSELLERS-VPN.dmg'), ('*.deb', 'INSELLERS-VPN.deb'),
        ('*.app.tar.sig', 'INSELLERS-VPN-mac.app.tar.sig')])
    for file, name in files:
        url = base + name
        if not matches(url, file):
            print('Restoring', name, flush=True)
            subprocess.run(['curl', '-fsS', '--max-time', '420', '-X', 'POST', '-T', file,
                            '-H', 'Content-Type: application/octet-stream', '-H', '@-',
                            '-o', os.devnull, 'https://vpn.insellers.su/api/ci/desktop-upload?name=' + name + '&ver=' + version],
                           input=('X-CI-Key: ' + os.environ['DESKTOP_UPLOAD_KEY'] + '\n').encode(), check=True)
            if not matches(url, file):
                raise RuntimeError('New upload is unavailable')
        print('Verified', name, flush=True)
    name = 'contents/candidates/latest-' + version + '.json'
    listing = api('contents/candidates?ref=ci-logs')
    if any(row['name'] == 'latest-' + version + '.json' for row in listing):
        prior = json.loads(base64.b64decode(api(name + '?ref=ci-logs')['content']))
        if any(prior.get(k) != v for k, v in dict(**identity, platforms=platforms).items()):
            raise RuntimeError('Manifest already bound to different content')
        return
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    data = dict(**identity, platforms=platforms, notes='Тестовая версия INSELLERS VPN', pub_date=now)
    api(name, dict(message='Verify and restore candidate ' + version, branch='ci-logs',
                   content=base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()))


if __name__ == '__main__':
    identity = validate()
    if sys.argv[1:] == ['restore']:
        restore(identity)
    elif sys.argv[1:] != ['validate']:
        raise SystemExit(2)

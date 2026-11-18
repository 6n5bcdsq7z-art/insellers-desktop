"""Add the upstream TrustTunnel SOCKS client to the desktop overlay."""
import hashlib
import io
import json
import tarfile
import struct
import zipfile

from extra_bundle import put

ASSETS = {
    'universal-apple-darwin': ('macos-universal', 7416013, '932dff4f396811e31c64644bca422808bf3b79c45877aae7956429082a2c7214'),
    'x86_64-pc-windows-msvc': ('windows-x86_64', 6199997, '56fb620f4cd30abbc1b4586c6645b56d90c8c0e977ba53d95fb0f542acb7cb1f'),
    'x86_64-unknown-linux-gnu': ('linux-x86_64', 4236785, '75b7df59351e26462487464de5f3462153e00195f2d40677872fb93a5b44c488'),
}


def stage(desktop, cache, target, overlay, download):
    platform, size, digest = ASSETS[target]
    windows = platform.startswith('windows')
    stem = 'trusttunnel_client-v1.1.12-' + platform
    name = stem + ('.zip' if windows else '.tar.gz')
    url = 'https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v1.1.12/' + name
    download({'name':name,'url':url,'bytes':size,'sha256':digest}, cache)
    archive = (cache/name).read_bytes()
    if len(archive) != size or hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError("TrustTunnel archive checksum mismatch")
    if windows:
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            binary = package.read('trusttunnel_client.exe')
            license_text = package.read('LICENSE.txt')
    else:
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            binary = package.extractfile(stem+'/trusttunnel_client').read()
            license_text = package.extractfile(stem+'/LICENSE').read()
    base = desktop/'src-tauri'
    put(base/'binaries'/('trusttunnel-'+target+('.exe' if windows else '')), binary)
    if platform == 'macos-universal':
        # Tauri builds each architecture before merging its universal application.
        if binary[:4] != bytes.fromhex('cafebabe') or struct.unpack_from('>I', binary, 4)[0] != 2:
            raise ValueError('Expected two Mach-O slices')
        triples = {0x01000007:'x86_64-apple-darwin', 0x0100000c:'aarch64-apple-darwin'}
        for index in range(2):
            cpu, _, offset, length, _ = struct.unpack_from('>IIIII', binary, 8+20*index)
            triple = triples.pop(cpu)
            if length == 0 or offset+length > len(binary):
                raise ValueError('Invalid Mach-O slice')
            put(base/'binaries'/('trusttunnel-'+triple), binary[offset:offset+length])
    resource = 'resources/trusttunnel.LICENSE'
    put(base/resource, license_text, 0o644)
    config = json.loads(overlay.read_text())
    config['bundle']['externalBin'].append('binaries/trusttunnel')
    resources = config['bundle']['resources']
    if isinstance(resources,dict):
        resources[resource] = resource
    else:
        resources.append(resource)
    overlay.write_text(json.dumps(config,indent=2)+'\n')

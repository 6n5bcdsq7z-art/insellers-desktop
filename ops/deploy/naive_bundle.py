#!/usr/bin/env python3
"""Stage verified upstream Naive engines without altering an app or releasing it.

An explicit target OS floor prevents bundling a macOS 13 engine into an app
that promises macOS 11. Android binaries are PIE executables named .so, not
JNI libraries: they must be extracted by the installer before ProcessBuilder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tarfile
import tempfile
import zipfile

MANIFEST = Path(__file__).with_name("naive-assets.json")


def inspect_binary(data, platform, machine):
    if platform.startswith("mac-"):
        if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("expected thin 64-bit Mach-O")
        _, cpu, _, kind, ncmds, command_bytes, _, _ = struct.unpack_from("<8I", data)
        if cpu != machine or kind != 2 or command_bytes > len(data) - 32:
            raise ValueError("unexpected Mach-O architecture/type")
        offset, minimum = 32, None
        for _ in range(ncmds):
            if offset + 8 > 32 + command_bytes:
                raise ValueError("truncated Mach-O commands")
            cmd, size = struct.unpack_from("<2I", data, offset)
            if size < 8 or offset + size > 32 + command_bytes:
                raise ValueError("invalid Mach-O command")
            if cmd == 0x32:
                if size < 24:
                    raise ValueError("truncated build-version command")
                target, version = struct.unpack_from("<2I", data, offset + 8)
                if target != 1 or minimum is not None:
                    raise ValueError("unexpected Mach-O platform")
                minimum = (version >> 16, (version >> 8) & 255, version & 255)
            offset += size
        if minimum is None:
            raise ValueError("missing macOS compatibility floor")
        return {"format": "Mach-O", "machine": machine, "minimum_macos": list(minimum)}
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1 or data[4] not in (1, 2):
        raise ValueError("expected little-endian ELF")
    bits = 64 if data[4] == 2 else 32
    kind, actual = struct.unpack_from("<HH", data, 16)
    if kind != 3 or actual != machine:
        raise ValueError("unexpected PIE architecture/type")
    if bits == 64:
        off = struct.unpack_from("<Q", data, 32)[0]
        entry, count = struct.unpack_from("<HH", data, 54)
        size, fmt = 56, "<IIQQQQQQ"
    else:
        off = struct.unpack_from("<I", data, 28)[0]
        entry, count = struct.unpack_from("<HH", data, 42)
        size, fmt = 32, "<IIIIIIII"
    if entry != size or off + count * entry > len(data):
        raise ValueError("invalid ELF program headers")
    alignments, interpreter = [], None
    for i in range(count):
        values = struct.unpack_from(fmt, data, off + i * entry)
        if bits == 64:
            ptype, _, offset, _, _, length, _, align = values
        else:
            ptype, offset, _, _, length, _, _, align = values
        if ptype == 1:
            alignments.append(align)
        if ptype == 3:
            if offset + length > len(data):
                raise ValueError("truncated ELF interpreter")
            interpreter = data[offset:offset + length].rstrip(b"\0").decode("ascii")
    if not alignments or not interpreter:
        raise ValueError("incomplete executable")
    if platform.startswith("android-"):
        expected = "/system/bin/linker64" if bits == 64 else "/system/bin/linker"
        if interpreter != expected:
            raise ValueError("not an Android executable")
        if bits == 64 and min(alignments) < 16384:
            raise ValueError("Android arm64 executable lacks 16 KiB LOAD alignment")
    return {"format": "ELF-PIE", "machine": machine, "bits": bits,
            "interpreter": interpreter, "load_alignment": min(alignments)}


def stage(platform, archive, output, *, minimum_macos=None):
    manifest = json.loads(MANIFEST.read_text())
    asset = next((a for a in manifest["assets"] if a["platform"] == platform), None)
    if asset is None:
        raise ValueError("unsupported platform")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite a staged bundle")
    if archive.stat().st_size != asset["bytes"] or hashlib.sha256(archive.read_bytes()).hexdigest() != asset["sha256"]:
        raise ValueError("archive checksum/size mismatch")
    license_data = MANIFEST.with_name("naive.LICENSE").read_bytes()
    if hashlib.sha256(license_data).hexdigest() != manifest["license_sha256"]:
        raise ValueError("upstream license checksum mismatch")
    if archive.suffix == ".apk":
        with zipfile.ZipFile(archive) as z:
            members = [m for m in z.infolist() if m.filename == asset["member"]]
            if len(members) != 1 or members[0].file_size > 64 * 1024 * 1024:
                raise ValueError("ambiguous or oversized engine")
            mode = members[0].external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("engine must not be a symlink")
            binary = z.read(members[0])
    else:
        with tarfile.open(archive) as t:
            members = [m for m in t.getmembers() if m.name == asset["member"]]
            if len(members) != 1 or not members[0].isfile() or members[0].size > 64 * 1024 * 1024:
                raise ValueError("ambiguous or unsafe engine member")
            binary = t.extractfile(members[0]).read()
            license_member = t.getmember(str(Path(asset["member"]).parent / "LICENSE"))
            if not license_member.isfile() or license_member.size > 65536:
                raise ValueError("missing or unsafe upstream license")
            if t.extractfile(license_member).read() != license_data:
                raise ValueError("unexpected upstream license")
    details = inspect_binary(binary, platform, asset["machine"])
    if platform.startswith("mac-"):
        if minimum_macos is None or tuple(minimum_macos) < tuple(details["minimum_macos"]):
            raise ValueError("Naive requires macOS 13; use an explicit compatible feature gate, not the app-wide macOS 11 floor")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=".naive-stage-", dir=output.parent))
    try:
        name = "libnaive.so" if platform.startswith("android-") else "naive"
        (temp / name).write_bytes(binary)
        (temp / name).chmod(0o755)
        if license_data:
            (temp / "LICENSE").write_bytes(license_data)
        receipt = dict(version=manifest["version"], platform=platform, source_url=asset["url"],
            archive_sha256=asset["sha256"], binary_sha256=hashlib.sha256(binary).hexdigest(),
            binary=name, verified=details, app_integrated=False, signed_app=False,
            requires_extracted_native_lib=platform.startswith("android-"))
        (temp / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        # Rename a directory, never copy over a possibly working app bundle.
        os.rename(temp, output)
        return receipt
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("platform")
    p.add_argument("archive", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--minimum-macos", help="Explicit feature OS floor, e.g. 13.0.0")
    a = p.parse_args()
    minimum = tuple(int(x) for x in a.minimum_macos.split(".")) if a.minimum_macos else None
    if minimum is not None and len(minimum) != 3:
        p.error("minimum macOS requires major.minor.patch")
    print(json.dumps(stage(a.platform, a.archive, a.output, minimum_macos=minimum), indent=2))


if __name__ == "__main__":
    main()

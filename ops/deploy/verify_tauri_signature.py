#!/usr/bin/env python3
"""Verify a Tauri/minisign updater signature with the system OpenSSL."""

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def _text_lines(encoded: str, label: str) -> list[str]:
    try:
        text = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} is not valid base64-encoded minisign text") from exc
    lines = text.strip().splitlines()
    if len(lines) < 2:
        raise ValueError(f"{label} has no minisign payload")
    return lines


def _digest(path: Path) -> bytes:
    value = hashlib.blake2b(digest_size=64)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.digest()


def verify(config: Path, file: Path, signature: Path) -> None:
    settings = json.loads(config.read_text(encoding="utf-8"))
    public_text = settings["plugins"]["updater"]["pubkey"]
    public_blob = base64.b64decode(_text_lines(public_text, "public key")[1], validate=True)
    if len(public_blob) != 42 or public_blob[:2] != b"Ed":
        raise ValueError("configured updater public key is not a minisign Ed25519 key")

    signature_blob = base64.b64decode(
        _text_lines(signature.read_text(encoding="ascii"), "signature")[1],
        validate=True,
    )
    if len(signature_blob) != 74 or signature_blob[:2] not in (b"Ed", b"ED"):
        raise ValueError("updater signature is not a minisign Ed25519 signature")
    if signature_blob[2:10] != public_blob[2:10]:
        raise ValueError("updater signature key id does not match the configured key")

    with tempfile.TemporaryDirectory(prefix="tauri-signature-") as directory:
        root = Path(directory)
        public_der = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00" + public_blob[10:]
        public_path = root / "public.der"
        signature_path = root / "signature.bin"
        message_path = root / "message.bin"
        public_path.write_bytes(public_der)
        signature_path.write_bytes(signature_blob[10:])
        # Tauri uses minisign's prehashed "ED" form: Ed25519 over BLAKE2b-512(file).
        if signature_blob[:2] == b"ED":
            message_path.write_bytes(_digest(file))
        else:
            message_path = file
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(public_path), "-keyform", "DER", "-rawin",
                "-in", str(message_path), "-sigfile", str(signature_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise ValueError(f"updater signature verification failed: {detail}")
    print(f"verified updater signature: {file} ({file.stat().st_size} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    verify(args.config, args.file, args.signature)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

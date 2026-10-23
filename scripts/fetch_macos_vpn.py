#!/usr/bin/env python3
"""Download a pinned, checksum-verified tun2socks binary for macOS."""
import argparse
import hashlib
from pathlib import Path
import tempfile
import urllib.request
import zipfile

FILES = {
    "x86_64": ("amd64", "1e47114546cda37a3ab03867aca5b78bb1ccaf41356e39d572a3ef398114d361",
               "8abb313135637439ecf2b38dada78703336af27596cdee09b7cd592adc57c280"),
    "arm64": ("arm64", "b3c508a09116d5c4b63ea3b64ba54585a92ae84f3f94d73a9528b47357552da8",
              "c5c69e77679ead3eb89090b82d29376f0dfac25e64bea9f9ed90904828f68ab1"),
}

parser = argparse.ArgumentParser()
parser.add_argument("arch", choices=FILES)
args = parser.parse_args()
asset_arch, expected_archive, expected_binary = FILES[args.arch]
root = Path(__file__).resolve().parents[1] / "third_party" / "vpn" / f"macos-{args.arch}"
destination = root / "tun2socks"
if destination.is_file():
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_binary:
        raise SystemExit(f"Existing tun2socks binary failed SHA-256 verification: {destination}")
    print("Using existing macOS VPN binary:", destination)
    raise SystemExit(0)
url = f"https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-darwin-{asset_arch}.zip"
root.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory() as directory:
    archive = Path(directory) / "tun2socks.zip"
    urllib.request.urlretrieve(url, archive)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected_archive:
        raise SystemExit(f"tun2socks SHA-256 mismatch: expected {expected_archive}, got {actual}")
    with zipfile.ZipFile(archive) as source:
        member = f"tun2socks-darwin-{asset_arch}"
        destination.write_bytes(source.read(member))
if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_binary:
    raise SystemExit("Extracted tun2socks binary failed SHA-256 verification")
destination.chmod(0o755)
print(destination)

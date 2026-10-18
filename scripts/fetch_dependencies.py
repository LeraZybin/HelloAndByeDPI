"""Download pinned, checksum-verified source dependencies (Python 3.8+)."""
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request
import sys

ROOT = Path(__file__).resolve().parents[1] / "third_party"
DEPENDENCIES = [
    ("byedpi", "https://codeload.github.com/hufrea/byedpi/tar.gz/ba532298de7b28cfe854aea83d061369d13ca290",
     "c7211cfc0729d213219be9b67d774e375d75ae53bbf18b6af1967f06919bbac4"),
    ("wxWidgets", "https://github.com/wxWidgets/wxWidgets/releases/download/v3.2.6/wxWidgets-3.2.6.tar.bz2",
     "939e5b77ddc5b6092d1d7d29491fe67010a2433cf9b9c0d841ee4d04acb9dce7"),
]
if sys.platform == "win32":
    DEPENDENCIES.append(("curl", "https://curl.se/download/curl-8.17.0.tar.xz",
        "955f6e729ad6b3566260e8fef68620e76ba3c31acf0a18524416a185acf77992"))

def main():
    ROOT.mkdir(exist_ok=True)
    for name, url, digest in DEPENDENCIES:
        destination = ROOT / name
        if destination.exists():
            print("Using existing sources:", destination)
            continue
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as temp:
            stage = Path(temp)
            archive = stage / "source.tar"
            print("Downloading", name)
            urllib.request.urlretrieve(url, archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Checksum mismatch: " + name)
            unpacked = stage / "unpacked"
            unpacked.mkdir()
            with tarfile.open(archive) as source:
                for member in source:
                    parts = Path(member.name).parts[1:]
                    if not parts:
                        continue
                    target = unpacked.joinpath(*parts)
                    if ".." in parts or target.is_absolute() and unpacked not in target.parents:
                        raise RuntimeError("Unsafe archive entry")
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with source.extractfile(member) as src, target.open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                        target.chmod(member.mode & 0o777)
                    else:
                        raise RuntimeError("Unsupported archive entry: " + member.name)
            unpacked.rename(destination)
    proxy = ROOT / "byedpi" / "proxy.c"
    source = proxy.read_text()
    original = "    hints.ai_flags = AI_ADDRCONFIG;\n"
    replacement = """    #ifdef _WIN32
    // AI_ADDRCONFIG is unreliable on some Windows 8 network configurations
    // and can make getaddrinfo() reject otherwise valid public host names.
    hints.ai_flags = 0;
    #else
    hints.ai_flags = AI_ADDRCONFIG;
    #endif
"""
    if original in source:
        proxy.write_text(source.replace(original, replacement, 1))
    elif replacement not in source:
        raise RuntimeError("ByeDPI resolver patch no longer applies")
    print("Dependencies ready.")

if __name__ == "__main__":
    main()

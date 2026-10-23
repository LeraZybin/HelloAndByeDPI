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
    source = proxy.read_text()
    include_anchor = "    #include <netdb.h>\n"
    include_patch = """    #include <netdb.h>
    #ifdef __APPLE__
        #include <ifaddrs.h>
        #include <net/if.h>
    #endif
"""
    if include_patch not in source:
        if include_anchor not in source:
            raise RuntimeError("ByeDPI macOS interface include patch no longer applies")
        source = source.replace(include_anchor, include_patch, 1)
    bind_anchor = ("    if (bind(sfd, (struct sockaddr *)&params.baddr, \n"
                   "            SA_SIZE(&params.baddr)) < 0) {\n")
    bind_patch = """    #ifdef __APPLE__
    // A full-tunnel utun route would otherwise capture ByeDPI's own remote
    // sockets. Bind them to the physical interface selected by --conn-ip.
    struct ifaddrs *interfaces = NULL;
    if (params.baddr.sa.sa_family == AF_INET && getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *item = interfaces; item; item = item->ifa_next) {
            if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET)
                continue;
            struct sockaddr_in *candidate = (struct sockaddr_in *)item->ifa_addr;
            if (candidate->sin_addr.s_addr != params.baddr.in.sin_addr.s_addr)
                continue;
            unsigned int index = if_nametoindex(item->ifa_name);
            if (index && setsockopt(sfd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) < 0) {
                uniperror("setsockopt IP_BOUND_IF");
                freeifaddrs(interfaces);
                close(sfd);
                return -1;
            }
            break;
        }
        freeifaddrs(interfaces);
    }
    #endif
    if (bind(sfd, (struct sockaddr *)&params.baddr,
            SA_SIZE(&params.baddr)) < 0) {
"""
    if bind_patch not in source:
        if bind_anchor not in source:
            raise RuntimeError("ByeDPI macOS interface binding patch no longer applies")
        source = source.replace(bind_anchor, bind_patch, 1)
    proxy.write_text(source)
    print("Dependencies ready.")

if __name__ == "__main__":
    main()

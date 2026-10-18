#!/usr/bin/env python3
"""Copy the official app-local UCRT from a pinned Windows SDK NuGet package."""
import argparse
import hashlib
from pathlib import Path
import urllib.request
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('build', type=Path)
parser.add_argument('arch', choices=['x86', 'x64'])
parser.add_argument('--archive', type=Path, default=Path('third_party/windows-sdk-10.0.19041.5.nupkg'))
args = parser.parse_args()
url = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.19041.5/microsoft.windows.sdk.cpp.10.0.19041.5.nupkg'
sha256 = '35074cafacc99a47e87c25641f98e0952576487fe29607103f83d61540ad0523'
if not args.archive.exists():
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, args.archive)
if hashlib.sha256(args.archive.read_bytes()).hexdigest() != sha256:
    raise SystemExit('Windows SDK SHA-256 mismatch')
args.build.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(args.archive) as sdk:
    prefix = f'c/Redist/10.0.19041.0/ucrt/DLLs/{args.arch}/'
    names = [n for n in sdk.namelist() if n.startswith(prefix) and n.endswith('.dll')]
    if not any(n.endswith('/ucrtbase.dll') for n in names):
        raise SystemExit('Missing UCRT redistributable')
    for name in names:
        (args.build / Path(name).name).write_bytes(sdk.read(name))
license_dir = args.build / 'licenses'
license_dir.mkdir(exist_ok=True)
license_file = license_dir / 'Microsoft-Windows-SDK-License.rtf'
if not license_file.exists():
    urllib.request.urlretrieve('https://aka.ms/WinSDKLicenseURL', license_file)
(license_dir / 'Microsoft-UCRT-NOTICE.txt').write_text(
    'Microsoft Universal CRT — Windows SDK 10.0.19041.5\nCopyright Microsoft Corporation.\n'
    f'Source: {url}\nSHA-256: {sha256}\n'
    'License: https://aka.ms/WinSDKLicenseURL\n'
    'Deployment: https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment\n')
print(f'{args.arch}: copied {len(names)} official UCRT redistributable DLLs')

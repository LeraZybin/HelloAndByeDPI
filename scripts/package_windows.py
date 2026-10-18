#!/usr/bin/env python3
"""Package a Windows build with a small launcher and runtime DLLs in lib/."""
from pathlib import Path
import shutil
import sys
import zipfile

build, destination = map(Path, sys.argv[1:3])
architecture = sys.argv[3].lower() if len(sys.argv) > 3 else ('x64' if 'x64' in destination.name.lower() else 'x86')
if architecture not in ('x64', 'x86'):
    raise SystemExit('Architecture must be x64 or x86')
launcher = build / 'HelloAndByeDPI-launcher.exe'
application = build / 'HelloAndByeDPI.exe'
root_files = [build / 'ciadpi.exe']
lib_files = [application] + list(build.glob('*.dll'))
if architecture == 'x64':
    lib_files.append(build / 'tun2socks.exe')
for required in (launcher, *root_files, *lib_files):
    if not required.is_file():
        raise SystemExit(f'Missing required file: {required}')
for directory in ('data', 'licenses'):
    if not (build / directory).is_dir():
        raise SystemExit(f'Missing directory: {build / directory}')

vpn_text = '''Режим VPN направляет IPv4-трафик всех приложений через ByeDPI. При первом
запуске Windows запросит права администратора и установит подписанный драйвер
Wintun. Настройка адаптера выполняется в фоне, окно остаётся доступным.
''' if architecture == 'x64' else '''VPN-режим доступен в 64-битной сборке. Эта 32-битная версия предоставляет
системный HTTP/HTTPS-прокси и ручной SOCKS5.
'''
readme = f'''HelloAndByeDPI 0.6.1 — Windows {architecture}

Распакуйте весь архив в одну папку и запустите HelloAndByeDPI.exe.
Не запускайте приложение прямо из ZIP. Каталоги lib, data и licenses,
а также ciadpi.exe должны оставаться на своих местах. Runtime DLL и внутренние
компоненты VPN находятся в lib.

Простой режим: выберите стратегию и нажмите «Включить». В режиме системного
прокси приложение задаёт Windows HTTP/HTTPS-прокси через ByeDPI и восстанавливает
прежние настройки при отключении.

{vpn_text}

«Тест стратегий» сравнивает доступность сайтов. Списки сайтов, DNS и другие
параметры находятся в полной версии.

Сборка предназначена для Windows 8 и новее.

Приложение не подписано цифровым сертификатом.
'''

stage = build / 'bin'
temporary_stage = build / 'bin.stage'
if temporary_stage.exists():
    shutil.rmtree(temporary_stage)
(temporary_stage / 'lib').mkdir(parents=True)
shutil.copy2(launcher, temporary_stage / 'HelloAndByeDPI.exe')
for source in root_files:
    shutil.copy2(source, temporary_stage / source.name)
for source in lib_files:
    name = 'HelloAndByeDPI-core.exe' if source == application else source.name
    shutil.copy2(source, temporary_stage / 'lib' / name)
for directory in ('data', 'licenses'):
    shutil.copytree(build / directory, temporary_stage / directory)
(temporary_stage / 'README.txt').write_text(readme, encoding='utf-8-sig')
if stage.exists():
    shutil.rmtree(stage)
temporary_stage.replace(stage)

destination.parent.mkdir(parents=True, exist_ok=True)
temporary = destination.with_suffix('.tmp.zip')
with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(p for p in stage.rglob('*') if p.is_file()):
        archive.write(path, 'HelloAndByeDPI/' + path.relative_to(stage).as_posix())
with zipfile.ZipFile(temporary) as archive:
    if archive.testzip():
        raise SystemExit('Archive integrity check failed')
temporary.replace(destination)
print(destination)

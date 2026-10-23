# HelloAndByeDPI

Current version: **0.6.5**.

HelloAndByeDPI is a native desktop GUI for [ByeDPI](https://github.com/hufrea/byedpi). It runs a local anti-DPI proxy, applies the required network settings automatically, and restores the previous settings when disconnected.

The interface is available in English and Russian.

## Downloads

Choose the package for your system from [GitHub Releases](https://github.com/LeraZybin/HelloAndByeDPI/releases):

- **Windows x64:** proxy and system-wide VPN modes.
- **macOS Intel:** macOS 10.13 or newer, including the 2013 Intel MacBook Air.
- **macOS Apple Silicon:** macOS 11 or newer.

The builds are currently unsigned. Windows SmartScreen or macOS Gatekeeper may show a warning on first launch.

## Quick start

1. Download and extract the package. On Windows, keep the entire folder together.
2. Run `HelloAndByeDPI`.
3. Select a strategy and choose **Proxy** or **VPN** mode.
4. Click **Turn on**.

Proxy mode configures the operating system automatically. Applications that use the system proxy require no manual setup. If automatic configuration is disabled, use `127.0.0.1:1080`; the local engine accepts SOCKS5 and HTTP CONNECT.

VPN mode routes IPv4 traffic through ByeDPI using tun2socks. Windows uses Wintun; macOS uses a native `utun` adapter. The operating system requests administrator permission when routes are configured.
On macOS, the permission prompt appears once when VPN mode starts. The privileged tunnel supervisor removes its routes when you disconnect or if the application exits unexpectedly.

## Strategy testing

The application includes 60 strategies and the site lists from [romanvht/ByeByeDPI](https://github.com/romanvht/ByeByeDPI).

Open **Strategy test**, select the site lists, and start the test. Results are sorted by the number of accessible sites and median response time. Select a completed strategy to apply it. Custom site lists and custom strategies are supported in the full interface.

Disconnect other VPNs before starting VPN mode or strategy tests. The application checks for an active VPN and asks you to turn it off.

Test results depend on the provider, network, and active DPI equipment. A strategy that succeeds on one connection may fail on another.

## Main features

- Minimal and full interface modes.
- English and Russian localization.
- Automatic system proxy setup and rollback.
- System-wide VPN mode on Windows x64 and macOS.
- 60 built-in strategies, favorites, and custom strategies.
- Strategy testing with custom site lists, timeouts, retries, and CSV export.
- Recovery of network settings after an interrupted session.
- Session logs for troubleshooting.

Logging is off by default. Enable **Enable logging** in the main window or strategy tester while disconnected to collect troubleshooting logs. The setting is shared and saved. On Windows, the log is written to `HelloAndByeDPI.log` beside the executable.

## Website

The [download website](https://LeraZybin.github.io/HelloAndByeDPI/) deploys to GitHub Pages on every push to `main`. Its source is in `website/`; `python3 scripts/build_site.py` builds the static site in `build-site/` using the version from CMake.

## Compatibility

| Platform | Supported target | Available modes |
|---|---|---|
| Windows 8/8.1, 10, 11 x64 | 64-bit | Proxy and VPN |
| macOS Intel | 10.13+ | Proxy and VPN |
| macOS Apple Silicon | 11+ | Proxy and VPN |

Windows 8 compatibility is a build target and should still be verified on physical Windows 8 hardware. VPN mode has been tested on Windows 10 behind an active DPI connection.

## Build from source

Requirements: Python 3.8+, CMake 3.20+, and a C/C++ compiler.

```sh
python3 scripts/fetch_dependencies.py
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

For Windows, use MSYS2 MINGW64. MSVC and 32-bit Windows builds are not supported. The complete CI configuration is in [`.github/workflows/build.yml`](.github/workflows/build.yml).

## Third-party projects

- [ByeDPI](https://github.com/hufrea/byedpi), commit `ba532298de7b28cfe854aea83d061369d13ca290`
- [ByeByeDPI strategy lists](https://github.com/romanvht/ByeByeDPI), commit `96a3c1ff555043d915af814aa4f0e9a572c89aba`
- [wxWidgets](https://github.com/wxWidgets/wxWidgets) 3.2.6
- [tun2socks](https://github.com/xjasonlyu/tun2socks) 2.5.2
- [Wintun](https://www.wintun.net/) 0.14.1

Required third-party notices and licenses are included in release packages. The imported ByeByeDPI strategy data and its GPL-3.0 notice are stored in [`data/byebyedpi`](data/byebyedpi).

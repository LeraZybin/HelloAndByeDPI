# HelloAndByeDPI

HelloAndByeDPI is a native desktop GUI for [ByeDPI](https://github.com/hufrea/byedpi). It runs a local anti-DPI proxy, applies the required network settings automatically, and restores the previous settings when disconnected.

The interface is available in English and Russian.

## Downloads

Choose the package for your system from [GitHub Releases](https://github.com/LeraZybin/HelloAndByeDPI/releases):

- **Windows x64:** proxy and system-wide VPN modes.
- **Windows x86:** proxy mode for 32-bit Windows.
- **macOS Intel:** macOS 10.13 or newer, including the 2013 Intel MacBook Air.
- **macOS Apple Silicon:** macOS 11 or newer.

The builds are currently unsigned. Windows SmartScreen or macOS Gatekeeper may show a warning on first launch.

## Quick start

1. Download and extract the package. On Windows, keep the entire folder together.
2. Run `HelloAndByeDPI`.
3. Select a strategy and, on Windows x64, choose **Proxy** or **VPN** mode.
4. Click **Turn on**.

Proxy mode configures the operating system automatically. Applications that use the system proxy require no manual setup. If automatic configuration is disabled, use `127.0.0.1:1080`; the local engine accepts SOCKS5 and HTTP CONNECT.

VPN mode routes IPv4 traffic through ByeDPI using tun2socks and Wintun. Windows will request administrator permission when the adapter and routes are configured.

## Strategy testing

The application includes 60 strategies and the site lists from [romanvht/ByeByeDPI](https://github.com/romanvht/ByeByeDPI).

Open **Strategy test**, select the site lists, and start the test. Results are sorted by the number of accessible sites and median response time. Select a completed strategy to apply it. Custom site lists and custom strategies are supported in the full interface.

Test results depend on the provider, network, and active DPI equipment. A strategy that succeeds on one connection may fail on another.

## Main features

- Minimal and full interface modes.
- English and Russian localization.
- Automatic system proxy setup and rollback.
- Windows x64 VPN mode.
- 60 built-in strategies, favorites, and custom strategies.
- Strategy testing with custom site lists, timeouts, retries, and CSV export.
- Recovery of network settings after an interrupted session.
- Session logs for troubleshooting.

On Windows, the log is written to `HelloAndByeDPI.log` beside the executable.

## Compatibility

| Platform | Supported target | Available modes |
|---|---|---|
| Windows 8/8.1, 10, 11 x64 | 64-bit | Proxy and VPN |
| Windows 8/8.1, 10, 11 x86 | 32-bit | Proxy |
| macOS Intel | 10.13+ | Proxy |
| macOS Apple Silicon | 11+ | Proxy |

Windows 8 compatibility is a build target and should still be verified on physical Windows 8 hardware. VPN mode has been tested on Windows 10 behind an active DPI connection.

## Build from source

Requirements: Python 3.8+, CMake 3.20+, and a C/C++ compiler.

```sh
python3 scripts/fetch_dependencies.py
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

For Windows, use MSYS2 MINGW64 or MINGW32. MSVC is not supported by the bundled engine configuration. The complete CI configuration is in [`.github/workflows/build.yml`](.github/workflows/build.yml).

## Third-party projects

- [ByeDPI](https://github.com/hufrea/byedpi), commit `ba532298de7b28cfe854aea83d061369d13ca290`
- [ByeByeDPI strategy lists](https://github.com/romanvht/ByeByeDPI), commit `96a3c1ff555043d915af814aa4f0e9a572c89aba`
- [wxWidgets](https://github.com/wxWidgets/wxWidgets) 3.2.6
- [tun2socks](https://github.com/xjasonlyu/tun2socks) 2.5.2
- [Wintun](https://www.wintun.net/) 0.14.1

Required third-party notices and licenses are included in release packages. The imported ByeByeDPI strategy data and its GPL-3.0 notice are stored in [`data/byebyedpi`](data/byebyedpi).

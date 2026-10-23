#!/usr/bin/env python3
"""Collect a reproducible VPN report after the user disconnects other VPNs."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('1.1.1.1', '208.67.222.222')

class PreflightComplete(Exception):
    pass


def capture(command, timeout=8):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors='replace', timeout=timeout)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired) as error:
        return -1, str(error) + '\n'


def route_interfaces():
    interfaces = []
    for target in TARGETS:
        code, output = capture(['/sbin/route', '-n', 'get', target])
        if code:
            raise RuntimeError('Cannot inspect route to ' + target + ': ' + output)
        interface = next((line.split(':', 1)[1].strip() for line in output.splitlines()
                          if line.strip().startswith('interface:')), '')
        if not interface:
            raise RuntimeError('No interface in route output: ' + output)
        interfaces.append(interface)
    return interfaces


def snapshot(destination, scopes=()):
    commands = [
        ['/usr/bin/sw_vers'], ['/sbin/route', '-n', 'get', 'default'],
        *[['/sbin/route', '-n', 'get', target] for target in TARGETS],
        ['/usr/sbin/netstat', '-rn', '-f', 'inet'], ['/sbin/ifconfig'],
        ['/usr/sbin/scutil', '--dns'], ['/usr/sbin/scutil', '--proxy'],
        ['/usr/sbin/scutil', '--nwi'], ['/usr/sbin/scutil', '--nc', 'list'],
        ['/usr/sbin/networksetup', '-listallnetworkservices'],
    ]
    for interface in set(scopes):
        for target in TARGETS:
            commands.append(['/sbin/route', '-n', 'get', '-ifscope', interface, target])
    with destination.open('w') as output:
        for command in commands:
            code, text = capture(command)
            output.write('\n$ ' + ' '.join(command) + '\nexit=' + str(code) + '\n' + text)


def dns_settings():
    code, output = capture(['/usr/sbin/networksetup', '-listallnetworkservices'])
    if code:
        return {'error': output}
    settings = {}
    for service in output.splitlines()[1:]:
        service = service.lstrip('*').strip()
        if service:
            status, text = capture(['/usr/sbin/networksetup', '-getdnsservers', service])
            settings[service] = {'exit': status, 'dns': text.strip()}
    return settings


def run_phase(command, destination, env, timeout=180):
    print('Running:', destination.name, flush=True)
    with destination.open('w') as output:
        output.write('$ ' + ' '.join(command) + '\n'); output.flush()
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dns', default='system', help='system or a DNS IPv4 address (e.g. 1.1.1.1)')
    parser.add_argument('--check-only', action='store_true', help='collect preflight only; do not start VPN or send test requests')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('Run this command on the Mac being diagnosed.')
    if os.geteuid() == 0:
        parser.error('Run without sudo; macOS will request administrator authorization for the tunnel.')
    if args.dns != 'system':
        try:
            ipaddress.IPv4Address(args.dns)
        except ipaddress.AddressValueError:
            parser.error('--dns must be system or an IPv4 address')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    report = ROOT / 'reports' / ('mac-vpn-' + stamp + '-' + str(os.getpid()))
    report.mkdir(parents=True, mode=0o700)
    app_logs = report / 'application'; app_logs.mkdir(mode=0o700)
    app = ROOT / 'build/HelloAndByeDPI.app/Contents/MacOS'
    native = ROOT / 'build/vpn_network_mac'
    binaries = [app / 'HelloAndByeDPI', app / 'ciadpi', app / 'lib/tun2socks', native]
    env = os.environ.copy()
    env.update(HELLOBYE_DIAGNOSTICS='1', HELLOBYE_DIAGNOSTIC_DIR=str(app_logs),
               HELLOBYE_TEST_DNS='' if args.dns == 'system' else args.dns,
               PYTHONUNBUFFERED='1')
    results = {'dns': args.dns, 'started': datetime.datetime.now().isoformat(),
               'check_only': args.check_only, 'phases': {}, 'binaries': {}}
    stop_monitor = threading.Event()
    monitor = None
    original = None
    original_dns = None
    exit_code = 0
    print('Report:', report, flush=True)
    try:
        for binary in binaries:
            if not binary.is_file():
                raise RuntimeError('Missing build file: ' + str(binary))
            results['binaries'][str(binary)] = hashlib.sha256(binary.read_bytes()).hexdigest()
        snapshot(report / 'network-before.txt')
        original_dns = dns_settings()
        results['dns_before'] = original_dns
        original = route_interfaces()
        results['initial_interfaces'] = original
        if any(name.startswith(('utun', 'ppp', 'ipsec')) for name in original):
            raise RuntimeError('A VPN is still routing test traffic: ' + ', '.join(original) +
                               '. Disconnect it and run again. No VPN tests were started.')
        if args.check_only:
            print('Preflight complete. No VPN tests were started.', flush=True)
            raise PreflightComplete()
        with (report / 'dns-before.txt').open('w') as output:
            for host in ('example.com', 'youtube.com', 'www.youtube.com', 'ya.ru'):
                code, text = capture(['/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', host])
                output.write(host + ' exit=' + str(code) + '\n' + text + '\n')

        def monitor_routes():
            previous = None
            counter = 0
            with (report / 'route-monitor.jsonl').open('w') as output:
                while not stop_monitor.is_set():
                    try:
                        interfaces = route_interfaces()
                        output.write(json.dumps({'time': datetime.datetime.now().isoformat(),
                                                 'interfaces': interfaces}) + '\n'); output.flush()
                        if interfaces != previous:
                            snapshot(report / ('network-change-%02d.txt' % counter), original)
                            previous = interfaces; counter += 1
                    except Exception as error:
                        output.write(json.dumps({'error': str(error)}) + '\n'); output.flush()
                    stop_monitor.wait(1)
        monitor = threading.Thread(target=monitor_routes, daemon=True); monitor.start()
        results['phases']['external_https'] = run_phase(
            [str(native), str(app / 'ciadpi'), str(app / 'lib/tun2socks'), 'https://example.com/'],
            report / 'external-https.log', env)
        # Give the privileged supervisor time to finish route/DNS restoration.
        deadline = time.monotonic() + 15
        while route_interfaces() != original and time.monotonic() < deadline:
            time.sleep(.2)
        if route_interfaces() != original:
            raise RuntimeError('Initial routes were not restored after the first phase; second phase skipped.')
        results['phases']['strategies_11_14'] = run_phase(
            [sys.executable, str(ROOT / 'tests/policy_vpn_smoke.py'), str(app / 'HelloAndByeDPI')],
            report / 'policy-test-console.log', env)
        if any(results['phases'].values()):
            exit_code = 1
    except PreflightComplete:
        pass
    except KeyboardInterrupt:
        results['error'] = 'Interrupted by user'; exit_code = 130
    except Exception as error:
        results['error'] = str(error); print(str(error), flush=True); exit_code = 2
    finally:
        stop_monitor.set()
        if monitor:
            monitor.join(timeout=45)
        # Both tunnel supervisors also stop automatically when their parent exits.
        if original is not None:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if route_interfaces() == original:
                        results['routes_restored'] = True; break
                except RuntimeError:
                    pass
                time.sleep(.2)
            else:
                results['routes_restored'] = False; exit_code = 2
        if original_dns is not None and not args.check_only:
            deadline = time.monotonic() + 15
            while dns_settings() != original_dns and time.monotonic() < deadline:
                time.sleep(.2)
        snapshot(report / 'network-after.txt', original or ())
        if original_dns is not None:
            results['dns_after'] = dns_settings()
            results['dns_restored'] = original_dns == results['dns_after']
            if not results['dns_restored']:
                exit_code = 2
                print('DNS settings differ from their original values; see summary.json.', flush=True)
        results['exit_code'] = exit_code
        (report / 'summary.json').write_text(json.dumps(results, ensure_ascii=False, indent=2))
        archive_path = report.with_suffix('.zip')
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(report.rglob('*')):
                if path.is_file():
                    archive.write(path, path.relative_to(report.parent))
        print('Report ZIP:', archive_path, flush=True)
        print('Finished. You can reconnect your usual VPN.', flush=True)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())

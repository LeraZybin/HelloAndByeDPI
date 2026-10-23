"""macOS integration check; requests admin authorization and briefly changes IPv4 routes.

The HTTP fixture checks sequencing/results. An external HTTPS request checks
the actual VPN egress path; route inspection checks both halves of IPv4.
This is not a provider-DPI or Internet-speed test.
"""
import http.server
import subprocess
import sys
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(403 if self.path == '/denied' else 200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')


def route(address):
    output = subprocess.check_output(['/sbin/route', '-n', 'get', address], text=True)
    return next(line.split(':', 1)[1].strip() for line in output.splitlines()
                if line.strip().startswith('interface:'))


def main():
    targets = ('1.1.1.1', '208.67.222.222')
    original = [route(target) for target in targets]
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        process = subprocess.Popen([sys.argv[1], '--policy-ui-vpn-smoke-test',
                                    f'http://127.0.0.1:{server.server_port}'],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        observed = set()
        try:
            deadline = time.monotonic() + 120
            while process.poll() is None:
                for target in targets:
                    if route(target).startswith('utun'):
                        observed.add(target)
                if time.monotonic() > deadline:
                    raise TimeoutError('VPN test timed out, including administrator authorization')
                time.sleep(0.1)
            output = process.communicate()[0]
            print(output, end='')
            assert process.returncode == 0, f'UI exit: {process.returncode}'
            assert output.count('VPN smoke: tunnel startup requested') == 1, output
            assert 'VPN smoke: tunnel ready:' in output, output
            assert 'VPN smoke: tunnel stopped' in output, output
            assert observed == set(targets), f'VPN routes not observed for both IPv4 halves: {observed}'
        finally:
            if process.poll() is None:
                process.kill()
                print(process.communicate()[0], end='')
            deadline = time.monotonic() + 10
            while [route(target) for target in targets] != original and time.monotonic() < deadline:
                time.sleep(0.1)
            server.shutdown()
        assert [route(target) for target in targets] == original, 'Routes were not restored'
    print('VPN tester: one tunnel, two strategies, real utun routes, results/apply and cleanup passed')


if __name__ == '__main__':
    main()

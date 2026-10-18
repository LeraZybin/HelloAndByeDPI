"""Offline end-to-end tests: local HTTP/TLS servers and the real ByeDPI engine."""
import http.server
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            if self.path == '/slow':
                time.sleep(3)
            status = {'/denied': 403, '/missing': 404, '/redirect': 302}.get(self.path, 200)
            payload = b'x' * 131072 if self.path == '/large' else b'OK'
            self.send_response(status)
            if self.path == '/redirect':
                self.send_header('Location', '/ok')
            self.send_header('Content-Length', '1000' if self.path == '/partial' else str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def main():
    with tempfile.TemporaryDirectory() as directory:
        cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        http_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        tls.socket = context.wrap_socket(tls.socket, server_side=True)
        for server in (http_server, tls):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        proxy_port = port()
        engine = subprocess.Popen([sys.argv[1], '--ip', '127.0.0.1', '--port', str(proxy_port), '--split', '1'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if engine.poll() is not None:
                    raise RuntimeError(engine.stderr.read().decode(errors='replace'))
                try:
                    with socket.create_connection(('127.0.0.1', proxy_port), 1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.05)
            env = os.environ.copy()
            # The explicit per-request route must override both proxy and bypass environment settings.
            env.update(ALL_PROXY='socks5://127.0.0.1:1', http_proxy='http://127.0.0.1:1',
                       HTTPS_PROXY='http://127.0.0.1:1', NO_PROXY='*')
            subprocess.run([sys.argv[2], f'http://127.0.0.1:{http_server.server_port}', str(proxy_port),
                            f'https://127.0.0.1:{tls.server_port}/ok'], check=True, timeout=45, env=env)
            if len(sys.argv) > 3:
                subprocess.run([sys.argv[3], '--policy-ui-smoke-test', f'http://127.0.0.1:{http_server.server_port}'],
                               check=True, timeout=45)
                subprocess.run([sys.argv[3], '--policy-ui-apply-smoke-test', f'http://127.0.0.1:{http_server.server_port}'],
                               check=True, timeout=45)
                print('Policy tester GUI: languages, modes, live sorting, real policy #60, site results, apply and click-during-test passed')
        finally:
            engine.terminate()
            try:
                engine.wait(timeout=3)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.wait(timeout=3)
            engine.stderr.close()
            for server in (http_server, tls):
                server.shutdown()
                server.server_close()

if __name__ == '__main__':
    main()

"""Exercise the real bundled engine against a local server, without Internet."""
import socket
import struct
import subprocess
import sys
import threading
import time

def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("Unexpected EOF")
        result += part
    return result

with socket.socket() as server, socket.socket() as reservation:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(10)
    destination = server.getsockname()[1]
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()
    payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    failures = []
    def serve():
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                assert exact(connection, len(payload)) == payload
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        except Exception as error:
            failures.append(error)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    process = subprocess.Popen([sys.argv[1], "--ip", "127.0.0.1", "--port", str(port), "--split", "1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode(errors="replace"))
            try:
                client = socket.create_connection(("127.0.0.1", port), 1)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        with client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            assert exact(client, 2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", destination))
            header = exact(client, 4)
            assert header[:3] == b"\x05\x00\x00", header
            size = {1: 4, 4: 16}.get(header[3])
            if header[3] == 3:
                size = exact(client, 1)[0]
            assert size is not None
            exact(client, size + 2)
            client.sendall(payload)
            response = b""
            while not response.endswith(b"\r\n\r\nOK"):
                block = client.recv(4096)
                if not block:
                    break
                response += block
            assert response.endswith(b"\r\n\r\nOK"), response
        thread.join(5)
        assert not thread.is_alive()
        assert not failures, failures
        print("SOCKS5 negotiation and TCP forwarding passed")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stderr.close()

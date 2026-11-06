"""Internal-only test proxy: authenticated CONNECT to the fixture IP/port only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import ipaddress
import json
import select
import socket
import threading


class Handler(BaseHTTPRequestHandler):
    connects = 0
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path != '/metrics':
            self.send_error(404)
            return
        with Handler.lock:
            body = json.dumps({'connects': Handler.connects}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        expected = 'Basic ' + base64.b64encode(b'probe:isolated-proxy-only').decode()
        if self.headers.get('Proxy-Authorization') != expected:
            self.send_error(407)
            return
        try:
            host, port = self.path.rsplit(':', 1)
            numeric = str(ipaddress.ip_address(host.strip('[]')))
            allowed = {a[4][0] for a in socket.getaddrinfo('target', 8080, type=socket.SOCK_STREAM)}
            if numeric not in allowed or port != '8080':
                raise ValueError('unexpected destination')
        except ValueError:
            self.send_error(403)
            return
        with socket.create_connection((numeric, 8080), timeout=5) as upstream:
            with Handler.lock:
                Handler.connects += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            for _ in range(100):
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)


ThreadingHTTPServer(('0.0.0.0', 8081), Handler).serve_forever()

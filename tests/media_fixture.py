# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic ISO-BMFF transport fixture, not a playable course video."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import socket
import threading

MEDIA = b'\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp42' + (262152).to_bytes(4, 'big') + b'mdat' + bytes(range(256)) * 1024


@contextmanager
def server(mode='normal'):
    state = {'requests': [], 'broken': False, 'mode': mode, 'data': MEDIA}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            range_header = self.headers.get('Range', '')
            state['requests'].append((self.path, range_header, self.headers.get('Cookie', '')))
            probe = range_header == 'bytes=0-4095'
            current = state['mode']
            data = state['data']
            if current == 'redirect' and self.path != '/destination.mp4':
                self.send_response(302)
                self.send_header('Location', f'http://localhost:{self.server.server_port}/destination.mp4')
                self.end_headers()
                return
            if current == 'denied' or current == 'refresh' and 'fresh' not in self.path and not probe:
                self.send_response(403)
                self.end_headers()
                return
            if current in ('html', 'json', 'empty'):
                data = {'html': b'<html>secret</html>', 'json': b'{"secret":1}', 'empty': b''}[current]
            match = re.fullmatch(r'bytes=(\d+)-(\d*)', range_header)
            start = int(match[1]) if match else 0
            end = min(int(match[2]) if match and match[2] else len(data) - 1, len(data) - 1)
            if current == '416' and start > 0 or start >= len(data) and data:
                self.send_response(416)
                self.end_headers()
                return
            ranged = bool(match) and current not in ('ignore', 'unknown')
            body = data[start:end + 1] if ranged else data
            self.send_response(206 if ranged else 200)
            self.send_header('Content-Type', 'text/html' if current == 'html' else 'application/json' if current == 'json' else 'video/mp4')
            if current != 'unknown':
                self.send_header('Content-Length', str(len(body)))
            if ranged:
                self.send_header('Content-Range', 'invalid' if current == 'invalid' else f'bytes {start}-{end}/{len(data)}')
            self.end_headers()
            try:
                if current in ('disconnect', 'always-disconnect') and not probe and (not state['broken'] or current == 'always-disconnect'):
                    state['broken'] = True
                    self.wfile.write(body[:min(32768, len(body) // 2)])
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{httpd.server_port}/media.mp4', state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()

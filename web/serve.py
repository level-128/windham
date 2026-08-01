#!/usr/bin/env python3
"""Serve Windham Web with COOP/COEP headers (required for SharedArrayBuffer)
and on-the-fly gzip for static assets (.js/.wasm/.html/.css/.json)."""

import gzip
import http.server
import os
import sys

GZIP_TYPES = ('.js', '.wasm', '.html', '.css', '.json', '.txt', '.md')

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        super().end_headers()

    def do_GET(self):
        # Only compress when the client accepts gzip and the file is static.
        if 'gzip' not in self.headers.get('Accept-Encoding', ''):
            return super().do_GET()
        path = self.translate_path(self.path)
        if not os.path.isfile(path):
            return super().do_GET()
        if os.path.splitext(path)[1].lower() not in GZIP_TYPES:
            return super().do_GET()
        with open(path, 'rb') as f:
            raw = f.read()
        comp = gzip.compress(raw, 9)
        self.send_response(200)
        self.send_header('Content-Type', self.guess_type(path))
        self.send_header('Content-Length', str(len(comp)))
        self.send_header('Content-Encoding', 'gzip')
        self.send_header('Vary', 'Accept-Encoding')
        self.end_headers()
        self.wfile.write(comp)

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    serve_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), '..', 'build', 'web')
    os.chdir(serve_dir)
    print(f'Serving {os.getcwd()} at http://localhost:{port} (gzip enabled)')
    with http.server.HTTPServer(('', port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nShutting down.')

#!/usr/bin/env python3
"""Serve Windham Web with COOP/COEP headers (required for SharedArrayBuffer)."""

import http.server
import os
import sys

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        super().end_headers()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    serve_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), '..', 'build', 'web')
    os.chdir(serve_dir)
    print(f'Serving {os.getcwd()} at http://localhost:{port}')
    with http.server.HTTPServer(('', port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nShutting down.')

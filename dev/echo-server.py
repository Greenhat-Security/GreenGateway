#!/usr/bin/env python3

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        self._send_echo(include_body=False)

    def do_GET(self):
        self._send_echo()

    def do_POST(self):
        self._send_echo()

    def do_PUT(self):
        self._send_echo()

    def do_PATCH(self):
        self._send_echo()

    def do_DELETE(self):
        self._send_echo()

    def do_OPTIONS(self):
        self._send_echo()

    def _send_echo(self, include_body=True):
        parsed = urlsplit(self.path)
        body_length = int(self.headers.get("content-length", "0") or "0")
        raw_body = self.rfile.read(body_length) if body_length > 0 else b""
        response = {
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body": raw_body.decode("utf-8", errors="replace"),
        }
        response_body = json.dumps(response, sort_keys=True).encode("utf-8")

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response_body) if include_body else 0))
        self.end_headers()
        if include_body:
            self.wfile.write(response_body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", file=sys.stderr)


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), EchoHandler)
    print(f"dev echo server listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

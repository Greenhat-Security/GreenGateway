#!/usr/bin/env python3

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


MAX_LOAD_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 5 * 1024 * 1024
MAX_LOAD_DELAY_MS = 30_000
MAX_LOAD_RESPONSE_CHUNKS = 64
MAX_LOAD_CHUNK_DELAY_MS = 1_000


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
        try:
            raw_body, first_body_byte_epoch_ms, body_complete_epoch_ms = (
                self._read_request_body()
            )
        except (OSError, ValueError) as error:
            self.close_connection = True
            self._send_json(
                {"error": f"invalid request body: {error}"},
                status=400,
                include_body=include_body,
            )
            return
        upstream_id = os.environ.get("UPSTREAM_ID", "dev-echo")

        if parsed.path == "/__dev-control/stats":
            self._send_json(
                {
                    "upstream_id": upstream_id,
                    "accepted_connections": self.server.accepted_connections(),
                },
                include_body=include_body,
            )
            return

        if parsed.path == "/__dev-control/reset":
            self.server.reset_accepted_connections()
            self._send_json(
                {"status": "reset", "upstream_id": upstream_id},
                include_body=include_body,
            )
            return

        if parsed.path == "/ready":
            self._send_json(
                {"status": "ready", "upstream_id": upstream_id},
                include_body=include_body,
            )
            return

        if (
            parsed.path == "/__dev-echo/retry-probe"
            and os.environ.get("FAIL_RETRY_PROBE", "").lower() == "true"
        ):
            expected_request_ids = parse_qs(parsed.query).get(
                "__dev_expected_request_id",
                [],
            )
            expected_request_id = (
                expected_request_ids[0] if len(expected_request_ids) == 1 else None
            )
            if retry_probe_header_boundary_violation(
                self.headers,
                expected_request_id,
            ):
                self._send_json(
                    {"error": "header_boundary_violation"},
                    status=418,
                    include_body=include_body,
                )
                return
            self._send_json(
                {"error": "intentional retry probe failure", "upstream_id": upstream_id},
                status=503,
                include_body=include_body,
            )
            return

        if parsed.path == "/__dev-stream/inspect":
            self._send_json(
                {
                    "upstream_id": upstream_id,
                    "body_bytes": len(raw_body),
                    "first_body_byte_epoch_ms": first_body_byte_epoch_ms,
                    "body_complete_epoch_ms": body_complete_epoch_ms,
                },
                include_body=include_body,
            )
            return

        if parsed.path in {"/__dev-load", "/__dev-stream"}:
            query = parse_qs(parsed.query)
            delay_ms = bounded_query_int(query, "delay_ms", 0, MAX_LOAD_DELAY_MS)
            response_bytes = bounded_query_int(
                query,
                "response_bytes",
                0,
                MAX_LOAD_RESPONSE_BYTES,
            )
            status = bounded_query_int(query, "status", 100, 599, default=200)
            response_chunks = bounded_query_int(
                query,
                "response_chunks",
                1,
                MAX_LOAD_RESPONSE_CHUNKS,
                default=1,
            )
            chunk_delay_ms = bounded_query_int(
                query,
                "chunk_delay_ms",
                0,
                MAX_LOAD_CHUNK_DELAY_MS,
            )
            if delay_ms > 0:
                time.sleep(delay_ms / 1000)
            response_body = b"x" * response_bytes
            self.send_response(status)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("x-dev-upstream-id", upstream_id)
            self.send_header("content-length", str(len(response_body) if include_body else 0))
            self.end_headers()
            if include_body:
                response_parts = split_bytes(response_body, response_chunks)
                for chunk_index, chunk in enumerate(response_parts):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if chunk_index + 1 < len(response_parts) and chunk_delay_ms > 0:
                        time.sleep(chunk_delay_ms / 1000)
            return

        response = {
            "upstream_id": upstream_id,
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body": raw_body.decode("utf-8", errors="replace"),
        }
        self._send_json(response, include_body=include_body)

    def _read_request_body(self):
        transfer_encodings = [
            value.strip().lower()
            for value in self.headers.get("transfer-encoding", "").split(",")
            if value.strip()
        ]
        if transfer_encodings:
            if transfer_encodings != ["chunked"]:
                raise ValueError("unsupported transfer encoding")
            return self._read_chunked_request_body()

        raw_length = self.headers.get("content-length", "0") or "0"
        try:
            body_length = int(raw_length)
        except ValueError as error:
            raise ValueError("invalid content length") from error
        if body_length < 0 or body_length > MAX_REQUEST_BODY_BYTES:
            raise ValueError("request body exceeds the dev-server limit")
        raw_body = self.rfile.read(body_length) if body_length > 0 else b""
        if len(raw_body) != body_length:
            raise ValueError("incomplete request body")
        completed_at = epoch_millis()
        return raw_body, completed_at if raw_body else None, completed_at

    def _read_chunked_request_body(self):
        chunks = []
        total_length = 0
        first_body_byte_epoch_ms = None
        while True:
            size_line = self.rfile.readline(128)
            if not size_line.endswith(b"\r\n"):
                raise ValueError("invalid chunk size line")
            try:
                chunk_size = int(size_line[:-2].split(b";", 1)[0], 16)
            except ValueError as error:
                raise ValueError("invalid chunk size") from error
            if chunk_size < 0 or total_length + chunk_size > MAX_REQUEST_BODY_BYTES:
                raise ValueError("request body exceeds the dev-server limit")
            if chunk_size == 0:
                self._read_chunked_trailers()
                return (
                    b"".join(chunks),
                    first_body_byte_epoch_ms,
                    epoch_millis(),
                )

            chunk = self.rfile.read(chunk_size)
            if len(chunk) != chunk_size or self.rfile.read(2) != b"\r\n":
                raise ValueError("incomplete request body chunk")
            if first_body_byte_epoch_ms is None:
                first_body_byte_epoch_ms = epoch_millis()
            chunks.append(chunk)
            total_length += chunk_size

    def _read_chunked_trailers(self):
        total_length = 0
        for _ in range(32):
            trailer_line = self.rfile.readline(1024)
            total_length += len(trailer_line)
            if not trailer_line.endswith(b"\r\n") or total_length > 8192:
                raise ValueError("invalid chunk trailer")
            if trailer_line == b"\r\n":
                return
        raise ValueError("too many chunk trailers")

    def _send_json(self, value, status=200, include_body=True):
        response_body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header(
            "x-dev-upstream-id",
            os.environ.get("UPSTREAM_ID", "dev-echo"),
        )
        self.send_header("content-length", str(len(response_body) if include_body else 0))
        self.end_headers()
        if include_body:
            self.wfile.write(response_body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", file=sys.stderr)


def bounded_query_int(query, name, minimum, maximum, default=None):
    values = query.get(name)
    if not values:
        return minimum if default is None else default
    try:
        value = int(values[0])
    except (TypeError, ValueError):
        return minimum if default is None else default
    return max(minimum, min(maximum, value))


def retry_probe_header_boundary_violation(headers, expected_request_id):
    if headers.get("authorization") or headers.get("cookie"):
        return True
    request_id = headers.get("x-request-id", "")
    forwarded_for = headers.get("x-forwarded-for", "")
    real_ip = headers.get("x-real-ip", "")
    forwarding = f"{forwarded_for},{real_ip}"
    return (
        not expected_request_id
        or request_id != expected_request_id
        or not forwarded_for
        or real_ip != forwarded_for
        or "198.51.100.10" in forwarding
        or "198.51.100.11" in forwarding
    )


def epoch_millis():
    return time.time_ns() // 1_000_000


def split_bytes(value, requested_parts):
    if not value:
        return [b""]
    part_size = (len(value) + requested_parts - 1) // requested_parts
    return [
        value[offset : offset + part_size]
        for offset in range(0, len(value), part_size)
    ]


class CountingThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, request_handler_class):
        super().__init__(server_address, request_handler_class)
        self._accepted_connections = 0
        self._connection_lock = threading.Lock()

    def get_request(self):
        request, client_address = super().get_request()
        with self._connection_lock:
            self._accepted_connections += 1
        return request, client_address

    def accepted_connections(self):
        with self._connection_lock:
            return self._accepted_connections

    def reset_accepted_connections(self):
        with self._connection_lock:
            self._accepted_connections = 0


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = CountingThreadingHTTPServer(("0.0.0.0", port), EchoHandler)
    upstream_id = os.environ.get("UPSTREAM_ID", "dev-echo")
    print(
        f"dev echo server {upstream_id} listening on 0.0.0.0:{port}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

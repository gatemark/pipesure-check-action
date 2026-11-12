#!/usr/bin/env python3
# © Gatemark Systems Limited 2026. All rights reserved. Licensed under the Gatemark Pipesure Check Licence v0.1.
"""Local deterministic HTTP/HTTPS mock server for pipesure-check-action tests."""

import argparse
import http.server
import json
import ssl
import sys
import time


class MockHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        cfg = self.server.mock_cfg
        log_entry = {
            "method": "GET",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        with open(cfg["log_file"], "a", encoding="utf-8") as lf:
            lf.write(json.dumps(log_entry) + "\n")

        routes = cfg.get("routes", {})
        route = routes.get(self.path) or routes.get("*") or {"status": 404, "body": '{"message":"Not Found"}'}
        delay_ms = int(route.get("delay_ms", 0))
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        if "body_file" in route:
            with open(route["body_file"], "rb") as bf:
                body = bf.read()
        else:
            raw = route.get("body", "")
            body = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)

        status = int(route.get("status", 200))
        self.send_response(status)
        for hk, hv in route.get("headers", {}).items():
            self.send_header(hk, hv)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--routes", required=True)
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log-file", required=True)
    ap.add_argument("--tls-cert", default="")
    ap.add_argument("--tls-key", default="")
    args = ap.parse_args()

    with open(args.routes, "r", encoding="utf-8") as rf:
        routes = json.load(rf)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    httpd.mock_cfg = {"routes": routes, "log_file": args.log_file}
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    port = httpd.server_address[1]
    with open(args.port_file, "w", encoding="utf-8") as pf:
        pf.write(f"{port}\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

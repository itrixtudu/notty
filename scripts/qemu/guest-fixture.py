#!/usr/bin/env python3
"""Two guest-local HTTP endpoints with observable request counts."""
import http.server
import json
import pathlib
import signal
import sys
import threading

directory = pathlib.Path(sys.argv[1])
servers = []
lock = threading.Lock()
counts = {"198.18.0.1": 0, "198.18.0.2": 0}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        address = self.server.server_address[0]
        with lock:
            counts[address] += 1
            temporary = directory / "counts.tmp"
            temporary.write_text(json.dumps(counts) + "\n")
            temporary.replace(directory / "counts.json")
        body = (address + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


for address in counts:
    server = http.server.ThreadingHTTPServer((address, 18080), Handler)
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
directory.joinpath("counts.json").write_text(json.dumps(counts) + "\n")
directory.joinpath("ready").touch()
signal.pause()

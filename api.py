#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api.py -- serveur HTTP local stdlib-only pour l'OCCULTEUR.

    python api.py           # port 8787
    python api.py 9000      # port au choix
    PORT=8080 python api.py # port via environnement

Meme logique que l'API deployee (occulteur_logic.handle), zero dependance,
zero etat serveur, aucun log de contenu. Usage : developpement, demo,
auto-hebergement derriere un proxy. SANS garde par secret : a ne pas
exposer tel quel sur Internet — la version deployee vit derriere la
gateway RapidAPI.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from occulteur_logic import CORS, KNOWN_ROUTES, handle

DEFAULT_PORT = 8787


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status, payload=None):
        body = (json.dumps(payload, ensure_ascii=False).encode("utf-8")
                if payload is not None else b"")
        self.send_response(status)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _dispatch(self, method):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        status, payload = handle(method, self.path, body,
                                 self.headers.get("Content-Type") or "")
        self._respond(status, payload if payload else None)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def log_message(self, fmt, *args):
        # requetes loggees sans corps : aucune PII n'est jamais ecrite
        sys.stderr.write("%s %s\n" % (self.address_string(), args[0]))


def main():
    try:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT") or DEFAULT_PORT)
    except ValueError:
        port = DEFAULT_PORT
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"OCCULTEUR local : http://127.0.0.1:{port}  routes: {', '.join(KNOWN_ROUTES)}")
    print("Sans garde par secret — usage local uniquement.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nfermeture propre.")


if __name__ == "__main__":
    main()

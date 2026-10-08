#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
occulteur_logic.py -- pure request logic for the OCCULTEUR API (Law 0).

No workers SDK imports: fully unit-testable outside the Workers runtime.
worker.py is a thin SDK skin over handle(). Zero logging of payloads:
l'API ne stocke rien et n'écrit rien -- c'est un traitement de PII.

v1.4-logic (2026-10-08, revue Serrement des Serres Kimi) :
  - JSON-sniffing CONSERVATEUR : un log brut commençant par '{' ou '['
    (le cas d'usage n°1 de /scan !) n'est plus rejeté 400. Le content-type
    prime ; le sniffing ne déballe que les payloads wrapper valides.
  - Borne anti-DoS amont : body brut refusé > MAX_RAW_BODY (413) avant
    tout parsing JSON.
  - Oversize moteur (MAX_CHARS) mappé en 413 (et non 400).
  - Rate limit glissant 30/min/IP, IP fournie par le worker (XFF).
"""

import json
import time
import urllib.parse
from collections import defaultdict, deque

import occulteur_engine as engine

VERSION = engine.VERSION
SERVICE = "occulteur-api"

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

KNOWN_ROUTES = ["/", "/health", "/mask", "/scan", "/restore"]
PHILOSOPHY = ("Le mapping ne voyage JAMAIS vers le LLM. Zero etat serveur. "
              "Couche B = suspicions signalees, jamais decidees seules.")

# Anti-DoS : la borne moteur est 50 000 chars (MAX_CHARS). Le body brut
# (JSON escaping inclus) ne doit jamais dépasser ~4x ; au-delà, 413 sans
# même parser. L'oversize moteur devient un 413 propre, pas un 400 flou.
MAX_RAW_BODY = 200_000
RATE_LIMIT = 30                               # requêtes par fenêtre par IP
RATE_WINDOW = 60.0                            # secondes

_hits = defaultdict(deque)


def _rate_limited(client):
    now = time.monotonic()
    window = _hits[client]
    while window and now - window[0] > RATE_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return True
    window.append(now)
    return False


def _parse_body(body_text, content_type):
    """-> (data_dict_or_None, raw_text_or_None, error_or_None)
    Conservateur : le content-type prime. Sans lui, on ne déballe que si
    le body parse ET est un dict wrapper avec une 'text' string — sinon
    c'est un document brut (un log JSON commence par '{', il EST le texte)."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "application/json":
        try:
            data = json.loads(body_text)
        except ValueError:
            return None, None, "invalid JSON body"
        if not isinstance(data, dict):
            return None, None, "send a JSON object or a raw text body"
        return data, None, None
    if body_text.lstrip()[:1] in "{[":
        try:
            data = json.loads(body_text)
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("text"), str):
            return data, None, None
        return None, body_text, None   # document brut, pas un wrapper
    return None, body_text, None


def _text_of(data, raw):
    if data is not None:
        if "text" not in data:
            return None, "send JSON {'text': '...'} or a raw text body"
        if not isinstance(data["text"], str):
            return None, "'text' must be a string"
        return data["text"], None
    return raw, None


def handle(method, path, body_text="", content_type="", client="unknown"):
    """Pure request logic -> (status, payload_dict)."""
    path = urllib.parse.urlsplit(path).path.rstrip("/") or "/"

    if method == "OPTIONS":
        return 204, {}

    if path == "/":
        return 200, {
            "service": SERVICE,
            "engine": "occulteur",
            "version": VERSION,
            "routes": KNOWN_ROUTES,
            "philosophy": PHILOSOPHY,
            "docs": "POST /mask or /scan with JSON {'text': '...', ...} or a "
                    "raw text body; POST /restore with JSON "
                    "{'masked_text': '...', 'mapping': {...}}",
        }

    if path == "/health":
        return 200, {"status": "ok", "version": VERSION, "engine": "loaded"}

    if path in ("/mask", "/scan", "/restore"):
        if method != "POST":
            return 405, {"error": f"POST only on {path}"}

        # Anti-DoS : borner le body brut avant tout parsing.
        if len(body_text) > MAX_RAW_BODY:
            return 413, {"error": "content too large "
                                  "(max %d characters)" % engine.MAX_CHARS}

        if _rate_limited(client):
            return 429, {"error": "rate limit exceeded"}

        data, raw, err = _parse_body(body_text, content_type)
        if err:
            return 400, {"error": err}

        if path == "/restore":
            if data is None:
                return 400, {"error": "restore requires JSON "
                                      "{'masked_text': '...', 'mapping': {...}}"}
            if not isinstance(data.get("masked_text"), str) or \
                    "mapping" not in data:
                return 400, {"error": "'masked_text' (string) and 'mapping' "
                                      "(object or null) are required"}
            try:
                return 200, {"restored_text":
                             engine.restore(data["masked_text"],
                                            data["mapping"])}
            except ValueError as e:
                return 400, {"error": str(e)}

        text, err = _text_of(data, raw)
        if err:
            return 400, {"error": err}

        kwargs = {}
        if data:
            for k in ("mode", "salt", "profile"):
                if data.get(k) is not None:
                    kwargs[k] = data[k]
            if data.get("detect_secrets") is not None:
                kwargs["detect_secrets"] = bool(data["detect_secrets"])
            for k in ("entities", "allowlist"):
                if data.get(k) is not None:
                    if not isinstance(data[k], list):
                        return 400, {"error": f"'{k}' must be a list"}
                    kwargs[k] = data[k]
        try:
            if path == "/mask":
                return 200, engine.mask(text, **kwargs)
            # scan() = contrat sortant : pas de mode/salt (sinon TypeError -> 500)
            kw_scan = {k: v for k, v in kwargs.items() if k not in ("mode", "salt")}
            return 200, engine.scan(text, **kw_scan)
        except ValueError as e:
            # Borne moteur MAX_CHARS -> 413 ; erreurs de config -> 400.
            if "trop long" in str(e):
                return 413, {"error": str(e)}
            return 400, {"error": str(e)}

    return 404, {
        "error": "route not forged yet",
        "path": path,
        "known_routes": KNOWN_ROUTES,
    }

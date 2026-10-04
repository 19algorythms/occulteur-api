#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
occulteur_logic.py -- pure request logic for the OCCULTEUR API (Law 0).

No workers SDK imports: fully unit-testable outside the Workers runtime.
worker.py is a thin SDK skin over handle(). Zero logging of payloads:
l'API ne stocke rien et n'écrit rien -- c'est un traitement de PII.
"""
import json
import urllib.parse

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


def _parse_body(body_text, content_type):
    """-> (data_dict_or_None, raw_text_or_None, error_or_None)"""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "application/json" or body_text.lstrip()[:1] in "{[":
        try:
            data = json.loads(body_text)
        except ValueError:
            return None, None, "invalid JSON body"
        if not isinstance(data, dict):
            return None, None, "send a JSON object or a raw text body"
        return data, None, None
    return None, body_text, None


def _text_of(data, raw):
    if data is not None:
        if "text" not in data:
            return None, "send JSON {'text': '...'} or a raw text body"
        if not isinstance(data["text"], str):
            return None, "'text' must be a string"
        return data["text"], None
    return raw, None


def handle(method, path, body_text="", content_type=""):
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
            return 200, (engine.mask(text, **kwargs) if path == "/mask"
                         else engine.scan(text, **kwargs))
        except ValueError as e:
            return 400, {"error": str(e)}

    return 404, {
        "error": "route not forged yet",
        "path": path,
        "known_routes": KNOWN_ROUTES,
    }

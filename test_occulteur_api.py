"""Batterie de tests — couche API OCCULTEUR (occulteur_logic.handle).
Pure logique, zero SDK Workers : les memes specs tournent dans le bac a sable
et dans le worker. 17 tests."""
import json
import sys
sys.path.insert(0, "/mnt/agents/output")
from occulteur_logic import handle, KNOWN_ROUTES

J = {"Content-Type": "application/json"}
PII = "Contactez jean.dupont@free.fr au 06 12 34 56 78"

def t_root():
    st, p = handle("GET", "/")
    assert st == 200 and p["service"] == "occulteur-api" and p["routes"] == KNOWN_ROUTES, p

def t_health():
    st, p = handle("GET", "/health")
    assert st == 200 and p["status"] == "ok" and p["engine"] == "loaded", p

def t_options_preflight():
    st, p = handle("OPTIONS", "/mask")
    assert st == 204 and p == {}, (st, p)

def t_404():
    st, p = handle("GET", "/nope")
    assert st == 404 and p["path"] == "/nope" and "/mask" in p["known_routes"], p

def t_405():
    st, p = handle("GET", "/mask")
    assert st == 405 and "POST only" in p["error"], p

def t_mask_json():
    st, p = handle("POST", "/mask", json.dumps({"text": PII}), "application/json")
    assert st == 200 and "[EMAIL_1]" in p["masked_text"] and "[PHONE_FR_1]" in p["masked_text"], p
    assert p["mapping"]["[EMAIL_1]"] == "jean.dupont@free.fr", p["mapping"]

def t_mask_raw_body():
    st, p = handle("POST", "/mask", PII, "text/plain; charset=utf-8")
    assert st == 200 and "[EMAIL_1]" in p["masked_text"], p

def t_mask_anonymize_aucun_mapping():
    st, p = handle("POST", "/mask", json.dumps({"text": PII, "mode": "anonymize"}), "application/json")
    assert st == 200 and p["mapping"] is None and "[EMAIL_1]" in p["masked_text"], p

def t_mask_hash_sans_sel_400():
    st, p = handle("POST", "/mask", json.dumps({"text": PII, "mode": "hash"}), "application/json")
    assert st == 400 and "sel" in p["error"], p

def t_mask_texte_manquant_400():
    st, p = handle("POST", "/mask", json.dumps({"mode": "tag"}), "application/json")
    assert st == 400 and "text" in p["error"], p

def t_mask_json_invalide_400():
    st, p = handle("POST", "/mask", "{pas du json", "application/json")
    assert st == 400 and "JSON" in p["error"], p

def t_mask_mode_invalide_400():
    st, p = handle("POST", "/mask", json.dumps({"text": PII, "mode": "weird"}), "application/json")
    assert st == 400, p

def t_scan_sans_masked_ni_mapping():
    st, p = handle("POST", "/scan", json.dumps({"text": PII}), "application/json")
    assert st == 200 and "masked_text" not in p and "mapping" not in p, p
    assert p["report"]["entities"] == {"email": 1, "phone_fr": 1}, p

def t_scan_raw_body():
    st, p = handle("POST", "/scan", PII, "text/plain")
    assert st == 200 and p["report"]["contains_pii"] is True, p

def t_restore_roundtrip():
    st, m = handle("POST", "/mask", json.dumps({"text": PII}), "application/json")
    st2, r = handle("POST", "/restore", json.dumps(
        {"masked_text": m["masked_text"], "mapping": m["mapping"]}), "application/json")
    assert st2 == 200 and r["restored_text"] == PII, r

def t_restore_anonymize_400():
    st, m = handle("POST", "/mask", json.dumps({"text": PII, "mode": "anonymize"}), "application/json")
    st2, r = handle("POST", "/restore", json.dumps(
        {"masked_text": m["masked_text"], "mapping": None}), "application/json")
    assert st2 == 400 and "irréversible" in r["error"].lower() or "IRR" in r["error"], r

def t_restore_exige_json():
    st, p = handle("POST", "/restore", PII, "text/plain")
    assert st == 400 and "JSON" in p["error"], p

ALL = [v for k, v in sorted(globals().items()) if k.startswith("t_")]
fails = []
for fn in ALL:
    try:
        fn()
        print(f"  PASS  {fn.__name__}")
    except Exception as e:
        fails.append(fn.__name__)
        print(f"  FAIL  {fn.__name__}: {type(e).__name__}: {e}")
print(f"\n{len(ALL)-len(fails)}/{len(ALL)} tests verts")
assert not fails, f"ÉCHECS: {fails}"

"""Batterie de tests — couche API OCCULTEUR (occulteur_logic.handle).
Pure logique, zero SDK Workers : les memes specs tournent dans le bac a sable
et dans le worker.

v2 (2026-10-08, contrat v1.4-logic) : ajout des specs qui verrouillent le
fix du JSON-sniffing conservateur + anti-DoS v1.3. Les 17 specs d'origine
sont inchangées (aucune ne touchait le contrat modifié)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
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

# --- Specs v2 : verrouillent le contrat v1.4-logic (fix du 2026-10-08) ---

def t_v2_json_log_brut_debute_acc_200():
    """LE fix : un log JSON brut (commence par '{', pas de clé 'text') est
    du TEXTE à scanner, pas une erreur. Avant v1.4 : 400 'invalid JSON body'."""
    raw_log = '{"timestamp": "2026-10-08", "msg": "contact "}'
    st, p = handle("POST", "/scan", raw_log, "text/plain; charset=utf-8", client="v2_accolade")
    assert st == 200, (st, p)
    st, p = handle("POST", "/scan", raw_log, "", client="v2_accolade2")  # même sans content-type
    assert st == 200, (st, p)

def t_v2_log_brut_debute_crochet_200():
    """Body brut commençant par '[' (stack trace) non-JSON -> 200, texte brut."""
    st, p = handle("POST", "/scan", "[ERROR] RuntimeError at line 42", "text/plain", client="v2_crochet")
    assert st == 200, (st, p)

def t_v2_wrapper_sniffe_sans_ct_200():
    """Backward compat : un vrai wrapper sans content-type est toujours déballé."""
    st, p = handle("POST", "/mask", json.dumps({"text": PII}), "", client="v2_sniff")
    assert st == 200 and "[EMAIL_1]" in p["masked_text"], p

def t_v2_text_non_string_400():
    """{'text': 123} -> 400 propre (avant : 500 TypeError)."""
    st, p = handle("POST", "/mask", json.dumps({"text": 123}), "application/json", client="v2_nonstr")
    assert st == 400 and "text" in p["error"], (st, p)

def t_v2_oversize_moteur_413():
    st, p = handle("POST", "/mask", json.dumps({"text": "x" * 50001}), "application/json", client="v2_413m")
    assert st == 413 and "trop long" in p["error"], (st, p)

def t_v2_body_brut_geant_413():
    st, p = handle("POST", "/scan", "y" * 300000, "text/plain", client="v2_413b")
    assert st == 413, (st, p)

def t_v2_rate_limit_429():
    last = None
    for _ in range(30):          # 30 requêtes : toutes passent
        last, _ = handle("POST", "/mask", json.dumps({"text": PII}),
                         "application/json", client="spec_bot")
    assert last == 200, last
    st, _ = handle("POST", "/mask", json.dumps({"text": PII}),   # la 31e : 429
                   "application/json", client="spec_bot")
    assert st == 429, st
    # autre client non affecté
    st, _ = handle("POST", "/mask", json.dumps({"text": PII}),
                   "application/json", client="spec_autre")
    assert st == 200, st

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

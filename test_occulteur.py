"""Batterie de tests — OCCULTEUR v1.2 (ex-Le Confesseur). 59 tests.
51 tests v1.1 préservés verbatim (non-régression) + 8 nouveaux :
NIR capture lâche 3 (DOM 971, corse minuscule, mois 00 rejeté),
CB-KEYWORD \b 1 (visa/visage), dates ISO 1, entities sur suspicions 2,
restore mapping vide 1."""
import sys
sys.path.insert(0, "/mnt/agents/output")
from occulteur_engine import (mask, restore, scan, luhn_ok, compute_nir_key, rib_key,
                              iban_ok, MAX_CHARS, VERSION)

def luhn_complete(prefix: str) -> str:
    d = prefix + "0"
    s = 0
    for i, c in enumerate(reversed(d)):
        x = int(c)
        if i & 1:
            x *= 2
            if x > 9: x -= 9
        s += x
    return prefix + str((10 - s % 10) % 10)

SIREN = luhn_complete("55210055")          # 9 chiffres Luhn
SIRET = luhn_complete("5521005540001")     # 14 chiffres Luhn
SIRET_LP = "35600000012345"                # exception La Poste
NIR13 = "1800275123456"
NIR = NIR13 + f"{compute_nir_key(NIR13):02d}"
NIR_CORSE = "180022B001234"
NIR_CORSE = NIR_CORSE + f"{compute_nir_key(NIR_CORSE):02d}"
RIB_BANK, RIB_BRANCH, RIB_ACC = "30002", "00550", "12345678901"
RIB_KEY = rib_key(RIB_BANK, RIB_BRANCH, RIB_ACC)
RIB = f"{RIB_BANK} {RIB_BRANCH} {RIB_ACC} {RIB_KEY:02d}"
BBAN = RIB_BANK + RIB_BRANCH + RIB_ACC + f"{RIB_KEY:02d}"
_iban_tmp = BBAN + "FR00"
_n = "".join(c if c.isdigit() else str(ord(c) - 55) for c in _iban_tmp)
IBAN_CD = 98 - int(_n) % 97
IBAN = "FR" + f"{IBAN_CD:02d}" + " " + " ".join(BBAN[i:i+4] for i in range(0, 23, 4))
assert iban_ok(IBAN), "fixture IBAN invalide"
CB = "4539 1488 0343 6467"
assert luhn_ok("4539148803436467")
TEL = "01 42 68 53 00"
TEL_INTL = "+33 6 12 34 56 78"
EMAIL = "jean.dupont@example.fr"
EMAIL_IDN = "elise.muller@exämple.fr"
SK = "sk-proj-AbCdEfGhIjKlMnOp1234567890"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"

# --- fixtures v1.1
STRIPE_TEST = "4242 4242 4242 4242"       # PAN de test Stripe (Luhn-valide)
FIX_TEL = "01 99 00 12 34"                # plage fiction 01 99
FIX_EMAIL = "contact@example.com"         # RFC 2606

def _run_sans_luhn1(n: int = 16) -> str:
    """Run de n chiffres Luhn-invalide dont AUCUNE suppression d'1 chiffre
    ne rend Luhn valide (donc jamais LUHN-1-ERROR). Déterministe."""
    base = list("1234567890123456")
    i = 0
    while True:
        d = "".join(base)
        if not luhn_ok(d) and not any(luhn_ok(d[:k] + d[k + 1:]) for k in range(n)):
            return d
        base[i % n] = str((int(base[i % n]) + 1) % 10)
        i += 1

CB_BROKEN = _run_sans_luhn1()
assert not luhn_ok(CB_BROKEN)

# ================================================================ tests v1.0

def t_nir_valide():
    r = mask(f"NIR : {NIR}")
    assert "[NIR_1]" in r["masked_text"] and r["report"]["entities"] == {"nir": 1}, r["masked_text"]

def t_nir_corse():
    r = mask(f"corse {NIR_CORSE}")
    assert r["report"]["entities"].get("nir") == 1, r

def t_nir_key_err():
    good = f"{compute_nir_key(NIR13):02d}"
    bad = good[:-1] + ("9" if good[-1] != "9" else "8")
    r = mask(f"num {NIR13}{bad}")
    assert "[NIR_1]" not in r["masked_text"]
    assert any(s["code"] == "NIR-KEY-ERR" for s in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_siren():
    r = mask(f"SIREN {SIREN}")
    assert "[SIREN_1]" in r["masked_text"], r["masked_text"]

def t_siret():
    r = mask(f"SIRET {SIRET} et groupe {SIRET[:3]} {SIRET[3:6]} {SIRET[6:9]} {SIRET[9:]}")
    assert r["report"]["entities"] == {"siret": 2}, r["report"]["entities"]

def t_siret_laposte():
    r = mask(f"la poste {SIRET_LP}")
    assert r["report"]["entities"].get("siret") == 1, r

def t_siren_pas_dans_siret():
    r = mask(f"SIRET {SIRET}")
    assert "siren" not in r["report"]["entities"], r["report"]["entities"]

def t_rib():
    r = mask(f"RIB : {RIB}")
    assert "[RIB_1]" in r["masked_text"], r["masked_text"]

def t_rib_lettres():
    acc = "A1B2C3D4E5F"
    k = rib_key(RIB_BANK, RIB_BRANCH, acc)
    r = mask(f"RIB {RIB_BANK} {RIB_BRANCH} {acc} {k:02d}")
    assert r["report"]["entities"].get("rib") == 1, r

def t_rib_mauvaise_cle_pas_masque():
    r = mask(f"RIB {RIB_BANK} {RIB_BRANCH} {RIB_ACC} 99")
    assert "[RIB_1]" not in r["masked_text"], r["masked_text"]

def t_iban():
    r = mask(f"virement {IBAN}")
    assert "[IBAN_1]" in r["masked_text"], r["masked_text"]

def t_tel():
    for t_ in (TEL, TEL_INTL, "0033 6 12 34 56 78"):
        r = mask(f"appelez {t_}")
        assert "[PHONE_FR_1]" in r["masked_text"], (t_, r["masked_text"])

def t_near_phone():
    r = mask("rappelle le 06 12 34 56 7 stp")
    assert "[PHONE_FR_1]" not in r["masked_text"]
    assert any(s["code"] == "NEAR-PHONE" for s in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_cb():
    r = mask(f"CB {CB}")
    assert "[CB_1]" in r["masked_text"], r["masked_text"]

def t_luhn_1_error():
    p15 = luhn_complete("12345678901234")       # 15 chiffres Luhn-valide
    broken = p15[:3] + "9" + p15[3:]            # insertion -> 16 chiffres non valides
    assert not luhn_ok(broken)
    r = mask(f"carte {broken}")
    assert "[CB_1]" not in r["masked_text"]
    assert any(s["code"] == "LUHN-1-ERROR" for s in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_email():
    r = mask(f"mailto {EMAIL} ou {EMAIL_IDN}")
    assert r["report"]["entities"].get("email") == 2, r["report"]["entities"]

def t_email_point_final():
    # régression v1.0 : un email suivi du point de fin de phrase doit être détecté
    r = mask(f"Écris à {EMAIL}. Merci.")
    assert r["report"]["entities"].get("email") == 1, r
    assert r["masked_text"].count("[EMAIL_1]") == 1 and "Merci." in r["masked_text"]

def t_missing_at():
    r = mask("écris à jean.dupont gmail.com rapidement")
    assert "[EMAIL_1]" not in r["masked_text"]
    assert any(s["code"] == "MISSING-AT" for s in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_secret_sk():
    r = mask(f"clé {SK}")
    assert r["report"]["entities"] == {"secret": 1} and "[SECRET_1]" in r["masked_text"]

def t_secret_jwt():
    r = mask(f"token {JWT}")
    assert "[SECRET_1]" in r["masked_text"], r["masked_text"]

def t_password():
    r = mask("mot de passe : hunter2!")
    assert "[PASSWORD_1]" in r["masked_text"] and "hunter2" not in r["masked_text"]
    assert "mot de passe" in r["masked_text"]

def t_url_credentials():
    r = mask("serveur ftp://admin:s3cret@ftp.entreprise.fr/fichier")
    assert "[URL_CREDENTIALS_1]" in r["masked_text"], r["masked_text"]

def t_date_pas_suspicion():
    r = mask("né le 14.02.1987 à Lyon, rdv 2026.10.02")
    codes = [s["code"] for s in r["report"]["suspicions"]]
    assert "DIGIT-RUN" not in codes and "NEAR-PHONE" not in codes, codes

def t_pas_de_pii():
    txt = "Bonjour, voici le rapport trimestriel : +12% de croissance, 2026."
    r = mask(txt)
    assert r["masked_text"] == txt and r["report"]["contains_pii"] is False

def t_determinisme():
    txt = f"mail {EMAIL}, tél {TEL}, siret {SIRET}, cb {CB}"
    r1, r2 = mask(txt), mask(txt)
    assert r1 == r2, "non déterministe"

def t_hash():
    txt = f"{EMAIL} et encore {EMAIL} et {EMAIL_IDN}"
    r = mask(txt, mode="hash", salt="sel-super-secret")
    toks = [d["token"] for d in r["report"]["details"]]
    assert toks[0] == toks[1] and toks[0] != toks[2], toks
    assert all(t.startswith("h:") and len(t) == 14 for t in toks)
    r2 = mask(txt, mode="hash", salt="sel-super-secret")
    assert r["masked_text"] == r2["masked_text"]

def t_hash_sans_sel_refuse():
    try:
        mask("x", mode="hash")
        assert False
    except ValueError:
        pass

def t_restore_roundtrip():
    txt = f"Contactez {EMAIL} au {TEL}, siret {SIRET}, rib {RIB}, nir {NIR}"
    r = mask(txt)
    assert restore(r["masked_text"], r["mapping"]) == txt

def t_entities_filter():
    txt = f"{EMAIL} et {TEL}"
    r = mask(txt, entities=["email"])
    assert "[EMAIL_1]" in r["masked_text"] and "[PHONE_FR_1]" not in r["masked_text"]

def t_trop_long():
    try:
        mask("x" * (MAX_CHARS + 1))
        assert False
    except ValueError:
        pass

def t_limites_affichees():
    r = mask("rien ici")
    assert r["limits"]["max_chars"] == MAX_CHARS and r["version"] == VERSION

# ================================================================ jalon 1 : allowlist

def t_allowlist_exact():
    r = mask(f"appelez {TEL} merci", allowlist=[TEL])
    assert "[PHONE_FR_1]" not in r["masked_text"] and r["report"]["allowlisted"] == 1, r

def t_allowlist_regex():
    r = mask(f"SIREN {SIREN}", allowlist=[r"regex:55210055\d"])
    assert "[SIREN_1]" not in r["masked_text"] and r["report"]["allowlisted"] == 1, r["masked_text"]

def t_allowlist_lenient_safe():
    # garde-fou : une vraie CB Luhn-valide HORS liste RESTE masquée en lenient
    r = mask(f"CB {CB}", profile="lenient")
    assert "[CB_1]" in r["masked_text"], r["masked_text"]

def t_allowlist_lenient_fixtures():
    txt = f"carte {STRIPE_TEST}, mail {FIX_EMAIL}, tél {FIX_TEL}"
    rl = mask(txt, profile="lenient")
    assert rl["masked_text"] == txt and rl["report"]["allowlisted"] == 3, rl
    rs = mask(txt, profile="strict")
    assert rs["masked_text"] != txt and rs["report"]["allowlisted"] == 0, rs

def t_allowlist_compteur():
    txt = f"{FIX_EMAIL} puis {FIX_EMAIL} et {TEL}"
    r = mask(txt, allowlist=[TEL, FIX_EMAIL])
    assert r["report"]["allowlisted"] == 3, r["report"]
    assert r["report"]["allowlisted_breakdown"].get("email") == 2, r["report"]

def t_allowlist_couche_b():
    # l'allowlist s'applique AUSSI aux suspicions (Couche B)
    rl = mask("écris à jean.dupont example.com rapidement", profile="lenient")
    assert not any(s["code"] == "MISSING-AT" for s in rl["report"]["suspicions"]), rl["report"]["suspicions"]
    assert rl["report"]["allowlisted"] == 1
    rs = mask("écris à jean.dupont example.com rapidement")
    assert any(s["code"] == "MISSING-AT" for s in rs["report"]["suspicions"])

def t_profile_inconnu_refuse():
    try:
        mask("x", profile="weird")
        assert False
    except ValueError:
        pass

# ================================================================ jalon 2 : /scan

def t_scan_sans_masked_ni_mapping():
    r = scan(f"mail {EMAIL}, tél {TEL}")
    assert "masked_text" not in r and "mapping" not in r
    assert r["report"]["entities"] == {"email": 1, "phone_fr": 1}, r["report"]["entities"]
    assert all("token" not in d for d in r["report"]["details"])

def t_scan_detection_identique_a_mask():
    txt = f"{EMAIL} et {SIRET} et {NIR}"
    rs, rm = scan(txt), mask(txt)
    assert rs["report"]["entities"] == rm["report"]["entities"]
    assert [d["position"] for d in rs["report"]["details"]] == [d["position"] for d in rm["report"]["details"]]

def t_scan_suspicions_visibles():
    r = scan("rappelle le 06 12 34 56 7 stp")
    assert any(s["code"] == "NEAR-PHONE" for s in r["report"]["suspicions"]), r["report"]["suspicions"]

# ================================================================ jalon 3 : keyword-window CB

def t_cb_keyword_present():
    r = mask(f"ma carte {CB_BROKEN} ne passe plus")
    s = [x for x in r["report"]["suspicions"] if x["code"] == "CB-KEYWORD"]
    assert s and s[0]["confidence"] == 0.4, r["report"]["suspicions"]

def t_cb_keyword_absent():
    r = mask(f"réf interne {CB_BROKEN} dossier")
    assert not any(x["code"] == "CB-KEYWORD" for x in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_cb_keyword_dates_tel_silencieux():
    r = mask("carte perdue : né le 14.02.1987, appelez le 01 42 68 53 00")
    assert not any(x["code"] == "CB-KEYWORD" for x in r["report"]["suspicions"]), r["report"]["suspicions"]

def t_cb_keyword_pas_de_doublon_luhn1():
    # spéc : CB-KEYWORD seulement si NON LUHN-1-ERROR
    p15 = luhn_complete("12345678901234")
    broken = p15[:3] + "9" + p15[3:]
    r = mask(f"carte {broken}")
    codes = [x["code"] for x in r["report"]["suspicions"]]
    assert "LUHN-1-ERROR" in codes and "CB-KEYWORD" not in codes, codes

# ================================================================ jalon 4 : mode anonymize

def t_anonymize_mapping_null():
    r = mask(f"contact {EMAIL}", mode="anonymize")
    assert "[EMAIL_1]" in r["masked_text"] and r["mapping"] is None, r

def t_anonymize_note_irreversible():
    r = mask("x", mode="anonymize")
    assert "RRÉVERSIBLE" in r["limits"]["usage_note"].upper(), r["limits"]["usage_note"]

def t_anonymize_deterministe_et_restore_refuse():
    txt = f"{EMAIL} au {TEL}"
    r1, r2 = mask(txt, mode="anonymize"), mask(txt, mode="anonymize")
    assert r1 == r2, "anonymize non déterministe"
    try:
        restore(r1["masked_text"], r1["mapping"])
        assert False
    except ValueError:
        pass

# ================================================================ optimisation : NIR élargi

def t_nir_sexe_3_4():
    # sexes 3 et 4 = immatriculation en cours (NIR réels)
    for sexe in ("3", "4"):
        base = sexe + NIR13[1:]
        nir = base + f"{compute_nir_key(base):02d}"
        r = mask(f"NIR : {nir}")
        assert r["report"]["entities"].get("nir") == 1, (sexe, r)

def t_nir_mois_etendu():
    # mois 20-42 / 50-99 documentés (mois de naissance inconnu)
    base = "1803075123456"   # mois 30
    nir = base + f"{compute_nir_key(base):02d}"
    r = mask(f"NIR : {nir}")
    assert r["report"]["entities"].get("nir") == 1, r

def t_nir_corse_2a():
    base = "180022A001234"
    nir = base + f"{compute_nir_key(base):02d}"
    assert mask(f"corse {nir}")["report"]["entities"].get("nir") == 1

# ================================================================ v1.2 : revue Serrement des Serres

def t_nir_dom():
    # départements 971-976 : dept à 3 chiffres, commune réduite à 2.
    # (v1.1 les attrapait DÉJÀ via le run-classifier quand contigus — le
    # regex lâche sécurise le chemin principal et les formes séparées)
    base = "1841297112345"
    nir = base + f"{compute_nir_key(base):02d}"
    r = mask(f"NIR : {nir}")
    assert r["report"]["entities"].get("nir") == 1, r

def t_nir_corse_minuscule():
    # 2a/2B en minuscules (v1.1 : non détecté — regex case-sensitive)
    base = "180122A001234".lower()
    nir = base + f"{compute_nir_key(base.upper()):02d}"
    r = mask(f"corse {nir}")
    assert r["report"]["entities"].get("nir") == 1, r

def t_nir_mois_00_rejete():
    # mois 00 = jamais un vrai NIR, même avec une clé 97 correcte.
    # Sécurité : ne doit pas sortir en NIR (réidentification d'un faux positif)
    base = "1840012123456"
    nir = base + f"{compute_nir_key(base):02d}"
    r = mask(f"NIR : {nir}")
    assert "nir" not in r["report"]["entities"], r["report"]["entities"]

def t_cb_keyword_visa_sans_faux_positif():
    # v1.2 : \b autour des mots-clés — « visage » ne déclenche plus CB-KEYWORD
    r = mask("il a un visage marqué, réf 1234567890123456 dossier")
    assert not any(s["code"] == "CB-KEYWORD" for s in r["report"]["suspicions"]), \
        r["report"]["suspicions"]
    # témoin positif : « visa » exact déclenche toujours
    r2 = mask("ma visa : 1234567890123456")
    assert any(s["code"] == "CB-KEYWORD" for s in r2["report"]["suspicions"]), \
        r2["report"]["suspicions"]

def t_date_iso_tiret_sans_suspicion():
    # v1.2 : "-" accepté par RE_DATELIKE — les dates ISO ne parasitent plus
    # les scans de logs avec DIGIT-RUN
    r = mask("backup du 2026-10-04 terminé, archivage 2026-01-31 ok")
    codes = [s["code"] for s in r["report"]["suspicions"]]
    assert "DIGIT-RUN" not in codes, codes

def t_entities_filtre_suspicions():
    # v1.2 : entities filtre AUSSI la Couche B (avant : trou d'API)
    r = mask("carte 1234 5678 9012 3456 et tel 0123456789", entities=["email"])
    assert r["report"]["suspicions"] == [], r["report"]["suspicions"]
    r2 = mask("carte 1234 5678 9012 3456", entities=["cb"])
    assert any(s["code"] == "CB-KEYWORD" for s in r2["report"]["suspicions"]), \
        r2["report"]["suspicions"]

def t_restore_mapping_vide_refuse():
    # v1.2 : jetons présents + mapping vide = oubli de mapping, pas un OK silencieux
    try:
        restore("contactez [EMAIL_1]", {})
        assert False, "restore a accepté un mapping vide avec jetons"
    except ValueError:
        pass
    # témoin : mapping vide SANS jeton = cas légitime, passe toujours
    assert restore("aucune pii ici", {}) == "aucune pii ici"

def t_luhn_limite_documentee():
    # limite assumée : tout run 13-19 Luhn-valide = CB (IMEI inclus) ET
    # l'usage_note de chaque réponse le dit noir sur blanc
    r = mask("rien")
    assert "Luhn" in r["limits"]["usage_note"], r["limits"]["usage_note"]
    rs = scan("rien")
    assert "Luhn" in rs["limits"]["usage_note"], rs["limits"]["usage_note"]


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

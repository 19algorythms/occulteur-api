"""Batterie de tests — Le Confesseur v1.0 (jalon 1). 24 tests.
Un par famille + near-miss + legit + déterminisme."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # repo root
from confesseur_engine import (mask, restore, luhn_ok, compute_nir_key, rib_key,
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
NIR_CORSE = "180022B00123" + "45"          # 2B -> on recalcule
NIR_CORSE = "180022B001234"                # 13 avec 2B
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
    # v1.3 : "h:" + SHA3-512 complet (128 hex) = 130 caractères.
    # L'ancien format tronqué (12 hex = 14 caractères) est révolu.
    assert all(t.startswith("h:") and len(t) == 130 for t in toks)
    assert all(all(c in "0123456789abcdef" for c in t[2:]) for t in toks)
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

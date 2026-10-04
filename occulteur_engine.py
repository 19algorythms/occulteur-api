"""
OCCULTEUR — moteur v1.2 (ex-Le Confesseur)
Cathédrale1995 Research Initiative — Forge API #2
Stdlib only. Déterministe byte-for-byte. Zéro état serveur.
Couche A = certitude (checksum valide) -> masquage automatique.
Couche B = suspicion -> signalée avec code + raison, jamais décidée seule.

v1.1 (2026-10-03) — punch-list items 1 à 4 + optimisation moteur :
  1. allowlist (chaînes exactes ou "regex:...") + profile "strict"/"lenient"
  2. scan() : contrôle sortant, report complet SANS masked_text SANS mapping
  3. fenêtre mot-clé CB : suspicion CB-KEYWORD (0.4) à ±60 caractères d'un
     mot-clé carte, seulement si Luhn-invalide ET non LUHN-1-ERROR
  4. mode "anonymize" : jetons tag, mapping jamais retourné, irréversible
  + NIR élargi : sexe 3/4/7/8 (immatriculation en cours) et mois de
    naissance 13 / 20-42 / 50-99 (mois inconnu) — la clé 97 reste le juge.
  + fix email : un email suivi du point de fin de phrase est désormais détecté
    (le lookahead rejetait le '.' final).

v1.2 (2026-10-04) — revue Serrement des Serres (Kimi) :
  1. NIR : capture lâche ([1-47-8][0-9ABab]{12} + clé) — corrige l'angle mort
     des DOM (départements 971-976 à 3 chiffres) et accepte 2a/2b minuscules.
     La structure détaillée (mois != 00, A/B uniquement en position département)
     est validée POST-capture ; la clé 97 reste le juge final.
  2. RE_CB_KEYWORD : frontières \b (visa ne matche plus "visage"/"visas"...).
  3. RE_DATELIKE : séparateur "-" accepté — les dates ISO (2026-10-04) ne
     génèrent plus de suspicion DIGIT-RUN parasite dans les logs.
  4. suspicions filtrées par `entities` (code -> type via SUSPICION_TYPE).
  5. restore() : jetons présents + mapping vide -> erreur explicite (mapping
     oublié ou mode anonymize) ; mapping None (anonymize) déjà rejeté.
  + Limite documentée : tout run de 13-19 chiffres Luhn-valide est traité
    comme une CB (faux positifs possibles : IMEI, numéros de série).
"""
import re, hmac, hashlib, unicodedata
from dataclasses import dataclass

MAX_CHARS = 50_000
VERSION = "1.2.0"
CB_KEYWORD_WINDOW = 60

# ---------------------------------------------------------------- checksums

def luhn_ok(d: str) -> bool:
    if not d.isdigit() or not (8 <= len(d) <= 19):
        return False
    s = 0
    for i, c in enumerate(reversed(d)):
        x = ord(c) - 48
        if i & 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0

def compute_nir_key(base13: str) -> int:
    """Clé NIR = 97 - (NIR_13 mod 97). Corse : 2A->19, 2B->18."""
    n = base13.upper().replace("2A", "19").replace("2B", "18")
    return 97 - (int(n) % 97)

def nir_ok(nir15: str) -> bool:
    """Juge = clé 97. Structure légère : mois jamais 00 ; 2A/2B (minuscules
    acceptés) uniquement en position département ; département 2 OU 3
    chiffres (DOM 971-976 : la commune est alors réduite à 2 chiffres,
    le total fait toujours 13)."""
    s = nir15.upper()
    if len(s) != 15:
        return False
    base, key = s[:13], s[13:]
    if not key.isdigit():
        return False
    if not base[3:5].isdigit() or base[3:5] == "00":   # mois 01-99, jamais 00
        return False
    if not (base[5:7].isdigit() or base[5:7] in ("2A", "2B")):
        return False
    core = base[:5] + base[7:]                          # hors département : chiffres uniquement
    if not core.isdigit():
        return False
    return compute_nir_key(base) == int(key)

def _rib_num(s: str):
    out = ""
    for c in s.upper():
        if c.isdigit():
            out += c
        elif "A" <= c <= "Z":
            out += str((ord(c) - 64) % 10)   # A=1 ... I=9, J=0, K=1 ...
        else:
            return None
    return int(out)

def rib_key(bank: str, branch: str, account: str):
    b, g, c = _rib_num(bank), _rib_num(branch), _rib_num(account)
    if b is None or g is None or c is None:
        return None
    return 97 - (89 * b + 15 * g + 3 * c) % 97

def rib_ok(bank, branch, account, key) -> bool:
    k = rib_key(bank, branch, account)
    return k is not None and k == int(key)

def iban_ok(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    if not re.fullmatch(r"FR\d{2}[A-Z0-9]{23}", s):
        return False
    r = s[4:] + s[:4]
    n = "".join(c if c.isdigit() else str(ord(c) - 55) for c in r)
    return int(n) % 97 == 1

def hamming1(a: str, b: str) -> bool:
    return len(a) == len(b) and sum(c1 != c2 for c1, c2 in zip(a, b)) == 1

def normalize_for_hash(v: str) -> str:
    v = unicodedata.normalize("NFKD", v)
    v = "".join(c for c in v if not unicodedata.combining(c))
    return re.sub(r"[^0-9a-z]+", "", v.lower())

# ---------------------------------------------------------------- détecteurs

@dataclass
class Finding:
    start: int; end: int; type: str; raw: str
    code: str; confidence: float; reason: str; priority: int

# NIR v1.2 : capture LÂCHE — sexe 1-4/7/8 puis 12 caractères alphanumériques
# (2A/2B Corse en position département, DOM 971-976 à 3 chiffres). Toute la
# structure fine est déléguée à nir_ok() ; la clé 97 reste le juge final.
RE_NIR   = re.compile(r"(?<![A-Z0-9])([1-47-8][0-9ABab]{12})(\d{2})(?![A-Z0-9])")
RE_RIB   = re.compile(r"(?<!\w)(\d{5})[\s.\-](\d{5})[\s.\-]([0-9A-Za-z]{11})[\s.\-](\d{2})(?!\w)")
RE_IBAN  = re.compile(r"(?<![A-Z0-9])(FR\d{2}(?:[\s.\-]?[A-Z0-9]{4}){5}[\s.\-]?[A-Z0-9]{3})(?![A-Z0-9])", re.IGNORECASE)
RE_PHONE_LOC  = re.compile(r"(?<!\d)0[1-9](?:[\s.\-]?\d{2}){4}(?!\d)")
RE_PHONE_INTL = re.compile(r"(?<![+\w])(?:\+33|0033)[\s.\-]?(0?[1-9](?:[\s.\-]?\d{2}){4})(?!\d)")
RE_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w\-])", re.UNICODE)
RE_RUN   = re.compile(r"\d(?:[\s.\-]?\d)+")
RE_PWD   = re.compile(r"(?i)\b(?:mot\s+de\s+passe|password|passwd|pwd)\b(\s*[:=]\s*)(\S+)")
RE_URLCRED = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:]+:[^\s/@]+@[^\s]+", re.IGNORECASE)
RE_MISSAT  = re.compile(r"\b([A-Za-zÀ-ÖØ-öø-ÿ]+[._][A-Za-zÀ-ÖØ-öø-ÿ]+)\s+"
                        r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:com|fr|org|net|io|dev|gouv\.fr))")
# v1.2 : "-" ajouté — les dates ISO (2026-10-04), reines des logs ciblés par
# /scan, ne génèrent plus de suspicion DIGIT-RUN parasite.
RE_DATELIKE = re.compile(r"^\d{2}[\s.\-]\d{2}[\s.\-]\d{4}$|^\d{4}[\s.\-]\d{2}[\s.\-]\d{2}$|^\d{2}[\s.\-]\d{2}[\s.\-]\d{2}$")
# v1.2 : frontières \b — "visa" ne matche plus "visage"/"visas" ; "carte(s)".
RE_CB_KEYWORD = re.compile(r"\bcarte\b|\bcartes\b|\bcb\b|\bvisa\b|\bmaster\s?card\b|\bpaiement\b|\bcard\b",
                           re.IGNORECASE)

RE_SECRETS = [
    ("openai",   re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_\-]{16,}\b")),
    ("stripe",   re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("github",   re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack",    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("aws",      re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt",      re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b")),
    ("generic",  re.compile(r"\bpk-[A-Za-z0-9]{16,}\b")),
]

LABEL = {"nir": "NIR", "siren": "SIREN", "siret": "SIRET", "rib": "RIB", "iban": "IBAN",
         "phone_fr": "PHONE_FR", "cb": "CB", "email": "EMAIL", "secret": "SECRET",
         "password": "PASSWORD", "url_credentials": "URL_CREDENTIALS"}
SECRET_TYPES = {"secret", "password", "url_credentials"}

# v1.2 : les suspicions sont rattachées à un type d'entité pour que le filtre
# `entities` s'applique aussi à la Couche B (avant : inconsistances d'API).
SUSPICION_TYPE = {"NIR-KEY-ERR": "nir", "LUHN-1-ERROR": "cb", "CB-KEYWORD": "cb",
                  "NEAR-PHONE": "phone_fr", "DIGIT-RUN": "phone_fr",
                  "MISSING-AT": "email"}

# ---------------------------------------------------------------- allowlist
# Profil "lenient" : fixtures publiques auto-allowlistées (liste documentée
# dans le README). Garde-fou : une vraie CB Luhn-valide hors de cette liste
# RESTE masquée. Les regex numériques sont comparées en fullmatch à la forme
# digits-only du candidat ; les autres en search sur la valeur brute.
LENIENT_ALLOWLIST = [
    # RFC 2606 / RFC 6761 : domaines et TLD réservés à la documentation/tests
    r"regex:(?i)@example\.(?:com|net|org|edu)$",
    r"regex:(?i)@[\w-]+\.test$",
    r"regex:(?i)\bexample\.(?:com|net|org|edu)\b",
    # PAN de test publics (Stripe / émetteurs), Luhn-valides par construction
    r"regex:4242424242424242",
    r"regex:4000000000000002",
    r"regex:4000000000009995",
    r"regex:4000000000000069",
    r"regex:5555555555554444",
    r"regex:378282246310005",
    r"regex:6011111111111117",
    r"regex:3056930009020004",
    # Plage téléphonique FR réservée à la fiction : 01 99 XX XX XX (+33/0033)
    r"regex:(?:0199|33199|0033199)\d{6}",
]

def _compile_allowlist(entries):
    """Sépare chaînes exactes et motifs 'regex:...' (compilés une fois par appel)."""
    exact, regexes = set(), []
    for e in entries or []:
        if not isinstance(e, str):
            raise ValueError("entrée allowlist non textuelle")
        if e.startswith("regex:"):
            regexes.append(re.compile(e[len("regex:"):]))
        else:
            exact.add(e)
    return exact, regexes

def _allowlisted(raw: str, exact, regexes) -> bool:
    r = raw.strip()
    if r in exact:
        return True
    d = re.sub(r"\D", "", raw)
    for rx in regexes:
        if rx.search(r):
            return True
        if d and rx.fullmatch(d):
            return True
    return False

def _classify_run(raw: str):
    d = re.sub(r"\D", "", raw)
    n = len(d)
    if n == 9 and luhn_ok(d):
        return "siren", "SIREN valide (Luhn)", 1.0
    if n == 14 and (d.startswith("356000000") or luhn_ok(d)):
        return "siret", "SIRET valide (Luhn)" if not d.startswith("356000000") else "SIRET valide (exception La Poste)", 1.0
    if n == 15 and nir_ok(d):
        return "nir", "NIR valide (clé 97)", 1.0
    if 13 <= n <= 19 and luhn_ok(d):
        return "cb", "Carte bancaire valide (Luhn)", 1.0
    return None

def detect(text: str, detect_secrets: bool = True, entities=None,
           allowlist=None, profile: str = "strict"):
    """Retourne (findings, suspicions, stats). stats['allowlisted'] compte les
    signaux ignorés (Couche A ET B) par l'allowlist / le profil lenient."""
    if profile not in ("strict", "lenient"):
        raise ValueError("profile doit être 'strict' ou 'lenient'")
    entries = list(allowlist or [])
    if profile == "lenient":
        entries = entries + LENIENT_ALLOWLIST
    exact, regexes = _compile_allowlist(entries)

    findings, suspicions = [], []
    allowed = None if entities in (None, ["all"]) else set(entities)

    def add(start, end, typ, raw, code, conf, reason, prio):
        if allowed is None or typ in allowed:
            findings.append(Finding(start, end, typ, raw, code, conf, reason, prio))

    if detect_secrets and (allowed is None or "secret" in allowed):
        for name, rx in RE_SECRETS:
            for m in rx.finditer(text):
                add(m.start(), m.end(), "secret", m.group(0), f"SECRET-{name.upper()}", 0.95,
                    f"pattern secret {name}", 0)
    if detect_secrets and (allowed is None or "password" in allowed):
        for m in RE_PWD.finditer(text):
            add(m.start(2), m.end(2), "password", m.group(2), "PASSWORD-PLAIN", 0.9,
                "mot de passe en clair après label", 7)
    if detect_secrets and (allowed is None or "url_credentials" in allowed):
        for m in RE_URLCRED.finditer(text):
            add(m.start(), m.end(), "url_credentials", m.group(0), "URL-CREDENTIALS", 0.95,
                "URL avec identifiants inline", 6)

    if allowed is None or "iban" in allowed:
        for m in RE_IBAN.finditer(text):
            if iban_ok(m.group(1)):
                add(m.start(1), m.end(1), "iban", m.group(1), "IBAN-MOD97", 1.0,
                    "IBAN FR valide (mod 97 = 1)", 1)
    if allowed is None or "rib" in allowed:
        for m in RE_RIB.finditer(text):
            if rib_ok(m.group(1), m.group(2), m.group(3), m.group(4)):
                add(m.start(), m.end(), "rib", m.group(0), "RIB-MOD97", 1.0,
                    "RIB valide (clé mod 97)", 2)
    if allowed is None or "nir" in allowed:
        for m in RE_NIR.finditer(text):
            base, key = m.group(1), m.group(2)
            if nir_ok(base + key):
                add(m.start(1), m.end(2), "nir", m.group(0), "NIR-KEY", 1.0,
                    "NIR valide (clé 97)", 3)
            else:
                comp = f"{compute_nir_key(base):02d}"
                if hamming1(comp, key):
                    suspicions.append({"code": "NIR-KEY-ERR", "position": [m.start(), m.end()],
                                       "confidence": 0.55,
                                       "reason": f"clé NIR {key} invalide, attendue {comp} (1 chiffre d'écart) : probable NIR mal recopié",
                                       "raw": m.group(0)})
    if allowed is None or "phone_fr" in allowed:
        for rx, intl in ((RE_PHONE_INTL, True), (RE_PHONE_LOC, False)):
            for m in rx.finditer(text):
                raw = m.group(0)
                if intl:
                    d = re.sub(r"\D", "", m.group(1))
                    if not (len(d) in (9, 10) and (len(d) == 9 or d[0] == "0")):
                        continue
                add(m.start(), m.end(), "phone_fr", raw, "PHONE-FR-FMT", 0.95,
                    "téléphone français structuré (10 chiffres, préfixe 01-09 / +33)", 4)
    if allowed is None or "email" in allowed:
        for m in RE_EMAIL.finditer(text):
            add(m.start(), m.end(), "email", m.group(0), "EMAIL-FMT", 0.95,
                "adresse email (format)", 5)

    for m in RE_RUN.finditer(text):
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        n = len(d)
        if n < 6 or RE_DATELIKE.match(raw.strip()):
            continue
        c = _classify_run(raw)
        if c:
            typ, reason, conf = c
            add(m.start(), m.end(), typ, raw, f"{typ.upper()}-CHECKSUM", conf, reason, 8)
        else:
            prefix = text[max(0, m.start() - 4):m.start()]
            plausible = d.startswith("0") or "+33" in prefix or "0033" in prefix
            if n == 15:
                comp = f"{compute_nir_key(d[:13]):02d}"
                if hamming1(comp, d[13:15]):
                    suspicions.append({"code": "NIR-KEY-ERR", "position": [m.start(), m.end()],
                                       "confidence": 0.55,
                                       "reason": f"clé NIR {d[13:15]} invalide, attendue {comp} (1 chiffre d'écart)",
                                       "raw": raw})
            luhn1_fired = False
            if 15 <= n <= 19 and not luhn_ok(d):
                for i in range(n):
                    if luhn_ok(d[:i] + d[i + 1:]):
                        suspicions.append({"code": "LUHN-1-ERROR", "position": [m.start(), m.end()],
                                           "confidence": 0.5,
                                           "reason": "Luhn devient valide en retirant 1 chiffre : CB probablement mal recopiée",
                                           "raw": raw})
                        luhn1_fired = True
                        break
            if 13 <= n <= 19 and not luhn_ok(d) and not luhn1_fired:
                w0, w1 = max(0, m.start() - CB_KEYWORD_WINDOW), m.end() + CB_KEYWORD_WINDOW
                kw = RE_CB_KEYWORD.search(text[w0:w1])
                if kw:
                    suspicions.append({"code": "CB-KEYWORD", "position": [m.start(), m.end()],
                                       "confidence": 0.4,
                                       "reason": f"run de {n} chiffres Luhn-invalide à ±{CB_KEYWORD_WINDOW} caractères "
                                                 f"du mot-clé « {kw.group(0).strip()} » : CB mal recopiée ou partielle ?",
                                       "raw": raw})
            if 7 <= n <= 13 and plausible and n != 10:
                suspicions.append({"code": "NEAR-PHONE", "position": [m.start(), m.end()],
                                   "confidence": 0.45,
                                   "reason": f"{n} chiffres, préfixe français plausible, longueur != 10 : numéro mal frappé ?",
                                   "raw": raw})
            elif 6 <= n <= 13 and any(ch in raw for ch in " .-"):
                suspicions.append({"code": "DIGIT-RUN", "position": [m.start(), m.end()],
                                   "confidence": 0.3,
                                   "reason": "run de chiffres groupés non identifié : fragment potentiellement découpé",
                                   "raw": raw})

    for m in RE_MISSAT.finditer(text):
        suspicions.append({"code": "MISSING-AT", "position": [m.start(), m.end()],
                           "confidence": 0.5,
                           "reason": f"'{m.group(1)}' suivi du domaine '{m.group(2)}' sans @ : email avec arobase oublié ?",
                           "raw": m.group(0)})

    # résolution des chevauchements : priorité de détecteur, puis longueur
    findings.sort(key=lambda f: (f.start, f.priority, -(f.end - f.start)))
    kept, occupied = [], []
    for f in findings:
        if any(f.start < e and f.end > s for s, e in occupied):
            continue
        kept.append(f)
        occupied.append((f.start, f.end))
    kept.sort(key=lambda f: f.start)
    suspicions = [s for s in suspicions if not any(s["position"][0] < e and s["position"][1] > st for st, e in occupied)]

    # v1.2 : le filtre `entities` s'applique aussi aux suspicions (Couche B)
    if allowed is not None:
        suspicions = [s for s in suspicions if SUSPICION_TYPE.get(s["code"]) in allowed]

    # --- allowlist : ignorée partout (Couche A ET Couche B), APRES la résolution
    # de chevauchements pour compter chaque signal visible une seule fois et
    # garder le span comme bloquant vis-à-vis des sous-détections.
    kept_a, suppressed = [], []
    for f in kept:
        (suppressed if _allowlisted(f.raw, exact, regexes) else kept_a).append(f)
    kept_s = []
    for s in suspicions:
        (suppressed if _allowlisted(s["raw"], exact, regexes) else kept_s).append(s)
    kept, suspicions = kept_a, kept_s
    breakdown = {}
    for x in suppressed:
        k = x.type if isinstance(x, Finding) else x["code"]
        breakdown[k] = breakdown.get(k, 0) + 1
    stats = {"allowlisted": len(suppressed), "allowlisted_breakdown": breakdown}
    return kept, suspicions, stats

# ---------------------------------------------------------------- API publique

USAGE_BASE = ("Le mapping ne voyage JAMAIS vers le LLM. L'API ne stocke rien. "
              "Couche B = suspicions signalées, jamais décidées seules. "
              "Limite : tout run de 13-19 chiffres Luhn-valide est traité comme "
              "une carte bancaire (faux positifs possibles : IMEI, numéros de "
              "série — allowlistez-les si besoin).")
USAGE_ANONYMIZE = ("Mode anonymize : IRRÉVERSIBLE par construction — aucun mapping n'est "
                   "produit ni retourné, la restauration est impossible. "
                   + USAGE_BASE)

def mask(text: str, mode: str = "tag", salt: str = None, detect_secrets: bool = True,
         entities=None, allowlist=None, profile: str = "strict") -> dict:
    if mode not in ("tag", "hash", "anonymize"):
        raise ValueError("mode doit être 'tag', 'hash' ou 'anonymize'")
    if mode == "hash" and not salt:
        raise ValueError("sel client requis en mode hash (ne quitte jamais le client)")
    if len(text) > MAX_CHARS:
        raise ValueError(f"texte trop long : {len(text)} > {MAX_CHARS}")
    kept, suspicions, stats = detect(text, detect_secrets, entities, allowlist, profile)
    counters, mapping, details, counts = {}, {}, [], {}
    parts, pos = [], 0
    for f in kept:
        counters[f.type] = counters.get(f.type, 0) + 1
        if mode == "hash":
            token = "h:" + hmac.new(salt.encode(), normalize_for_hash(f.raw).encode(),
                                    hashlib.sha256).hexdigest()[:12]
        else:
            token = f"[{LABEL[f.type]}_{counters[f.type]}]"
        if mode != "anonymize":
            mapping[token] = f.raw
        counts[f.type] = counts.get(f.type, 0) + 1
        details.append({"token": token, "type": f.type, "position": [f.start, f.end],
                        "original_length": len(f.raw), "code": f.code,
                        "confidence": f.confidence, "reason": f.reason})
        parts.append(text[pos:f.start]); parts.append(token); pos = f.end
    parts.append(text[pos:])
    return {
        "masked_text": "".join(parts),
        "report": {
            "contains_pii": any(f.type not in SECRET_TYPES for f in kept),
            "contains_secrets": any(f.type in SECRET_TYPES for f in kept),
            "entities": counts,
            "details": details,
            "suspicions": suspicions,
            "allowlisted": stats["allowlisted"],
            "allowlisted_breakdown": stats["allowlisted_breakdown"],
        },
        "mapping": mapping if mode != "anonymize" else None,
        "limits": {"max_chars": MAX_CHARS,
                   "usage_note": USAGE_ANONYMIZE if mode == "anonymize" else USAGE_BASE},
        "version": VERSION,
    }

def scan(text: str, detect_secrets: bool = True, entities=None,
         allowlist=None, profile: str = "strict") -> dict:
    """Contrôle sortant : report complet, SANS masked_text, SANS mapping.
    Même detect() que mask(), zéro duplication. Usages : audit logs,
    réponse LLM, CI pii-check."""
    if len(text) > MAX_CHARS:
        raise ValueError(f"texte trop long : {len(text)} > {MAX_CHARS}")
    kept, suspicions, stats = detect(text, detect_secrets, entities, allowlist, profile)
    counts, details = {}, []
    for f in kept:
        counts[f.type] = counts.get(f.type, 0) + 1
        details.append({"type": f.type, "position": [f.start, f.end],
                        "original_length": len(f.raw), "code": f.code,
                        "confidence": f.confidence, "reason": f.reason})
    return {
        "report": {
            "contains_pii": any(f.type not in SECRET_TYPES for f in kept),
            "contains_secrets": any(f.type in SECRET_TYPES for f in kept),
            "entities": counts,
            "details": details,
            "suspicions": suspicions,
            "allowlisted": stats["allowlisted"],
            "allowlisted_breakdown": stats["allowlisted_breakdown"],
        },
        "limits": {"max_chars": MAX_CHARS,
                   "usage_note": "Scan = contrôle sortant : rapport complet, jamais de texte "
                                 "masqué, jamais de mapping. " + USAGE_BASE},
        "version": VERSION,
    }

def restore(masked_text: str, mapping: dict) -> str:
    if mapping is None:
        raise ValueError("mapping absent : un texte produit en mode anonymize est "
                         "irréversible par construction")
    if not mapping and re.search(r"\[[A-Z_]+_\d+\]", masked_text):
        raise ValueError("jetons présents mais mapping vide : mapping oublié "
                         "ou texte issu du mode anonymize")
    out = masked_text
    for token in sorted(mapping, key=len, reverse=True):
        out = out.replace(token, mapping[token])
    return out

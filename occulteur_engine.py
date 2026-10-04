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
        re
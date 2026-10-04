import json
"""Démo OCCULTEUR v1.2 — exemples exécutables pour le README GitHub.
    python examples.py
Chaque exemple imprime entrée -> sortie réelle du moteur (déterministe)."""
from occulteur_engine import mask, restore, scan, compute_nir_key

def show(titre, bloc):
    print(f"\n{'='*72}\n{titre}\n{'='*72}")
    print(bloc)

# --- 1. Masquage de base (mode tag) : le mapping reste chez le client
r = mask("Contactez jean.dupont@free.fr au 06 12 34 56 78, "
         "SIRET 55210055400013, CB 4539 1488 0343 6467")
show("1. mask(mode='tag') — le mapping ne voyage JAMAIS vers le LLM",
     f"masked_text : {r['masked_text']}\n"
     f"entities    : {r['report']['entities']}\n"
     f"mapping     : {json.dumps(r['mapping'], ensure_ascii=False)}")

# --- 2. Contrôle sortant /scan : audit d'une réponse de LLM, rien ne fuite
r = scan("Le client jean.dupont@free.fr, téléphone 06 12 34 56 78, "
         "a un visage marqué ; réf 1234 5678 9012 3456.")
show("2. scan() — contrôle sortant : rapport complet, SANS masked_text ni mapping",
     f"contains_pii : {r['report']['contains_pii']}\n"
     f"entities     : {r['report']['entities']}\n"
     f"suspicions   : {[s['code'] for s in r['report']['suspicions']]}")

# --- 3. Mode anonymize : irréversible par construction
r = mask("Patient NIR 180027512345640", mode="anonymize")
show("3. mask(mode='anonymize') — IRRÉVERSIBLE, mapping jamais produit",
     f"masked_text : {r['masked_text']}\n"
     f"mapping     : {r['mapping']}\n"
     f"usage_note  : {r['limits']['usage_note'][:80]}...")

# --- 4. Allowlist : on éteint le faux positif proprement
r = mask("Serveur de démo : appelez le 01 99 12 34 56, "
         "carte de test 4242 4242 4242 4242", profile="lenient")
show("4. profile='lenient' — fixtures publiques allowlistées, le réel reste masqué",
     f"masked_text  : {r['masked_text']}\n"
     f"allowlisted  : {r['report']['allowlisted']} "
     f"{r['report']['allowlisted_breakdown']}")

# --- 5. Restore : le roundtrip, preuve que la souveraineté reste côté client
txt = "Facture pour société SIREN 552100554, email compta@acme.fr"
r = mask(txt)
show("5. restore() — roundtrip exact (mode tag)",
     f"original    : {txt}\n"
     f"restauré    : {restore(r['masked_text'], r['mapping'])}")

# --- 6. Nouveautés v1.2 : NIR DOM + Corse minuscule
dom = "1841297112345" + f"{compute_nir_key('1841297112345'):02d}"
corse = "180122a001234" + f"{compute_nir_key('180122A001234'):02d}"
r = mask(f"Guadeloupe {dom}, Corse {corse}")
show("6. v1.2 — NIR DOM (971) et corse minuscule détectés",
     f"masked_text : {r['masked_text']}\n"
     f"entities    : {r['report']['entities']}")

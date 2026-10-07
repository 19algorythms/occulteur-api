# OCCULTEUR v1.3 — Exemples

Chaque exemple ci-dessous est **généré par le moteur réel** (`python examples.py`),
pas rédigé à la main. Le moteur est déterministe byte-for-byte : vous reproduisez
exactement ces sorties chez vous.

```bash
git clone <repo> && cd <repo>
python api.py                # serveur local http://127.0.0.1:8787
python test_occulteur.py     # 59/59 specs v1.1+v1.2
python test_confesseur.py    # 30/30 specs v1.0 (non-régression via shim)
python test_occulteur_api.py # 17/17 specs couche API
python examples.py           # cette page, en direct
```

## 1. mask(mode='tag') — le mapping ne voyage JAMAIS vers le LLM

Les PII sont remplacées par des jetons numérotés. Le mapping complet reste dans la réponse **côté client** — il ne voyage jamais vers le LLM.

```text
masked_text : Contactez [EMAIL_1] au [PHONE_FR_1], SIRET [SIRET_1], CB [CB_1]
entities    : {'email': 1, 'phone_fr': 1, 'siret': 1, 'cb': 1}
mapping     : {"[EMAIL_1]": "jean.dupont@free.fr", "[PHONE_FR_1]": "06 12 34 56 78", "[SIRET_1]": "55210055400013", "[CB_1]": "4539 1488 0343 6467"}
```

## 2. scan() — contrôle sortant : rapport complet, SANS masked_text ni mapping

Aucun `masked_text`, aucun `mapping` : uniquement le rapport. Notez que « visage » (à ±60 caractères d'un run suspect) est **silencieux** depuis v1.2, et que le run Luhn-invalide déclenche `CB-KEYWORD` en suspicion, jamais en masquage.

```text
contains_pii : True
entities     : {'email': 1, 'phone_fr': 1}
suspicions   : []
```

Depuis v1.3, les suspicions de `scan()` n'ont **aucun champ `raw`** :
aucune valeur brute ne sort par le contrôle sortant.

## 3. mask(mode='anonymize') — IRRÉVERSIBLE, mapping jamais produit

Mêmes jetons que `tag`, mais aucun mapping n'est produit ni retourné : la restauration est impossible par construction. `usage_note` le dit en clair dans chaque réponse.

```text
masked_text : Patient NIR 180027512345640
mapping     : None
usage_note  : Mode anonymize : IRRÉVERSIBLE par construction — aucun mapping n'est produit ni ...
```

## 4. profile='lenient' — fixtures publiques allowlistées, le réel reste masqué

Le profil `lenient` auto-allowliste les fixtures documentées (RFC 2606, PAN de test, 01 99 XX XX XX). Une **vraie** CB hors liste reste masquée — testé par la spec `t_allowlist_lenient_safe`.

```text
masked_text  : Serveur de démo : appelez le 01 99 12 34 56, carte de test 4242 4242 4242 4242
allowlisted  : 2 {'phone_fr': 1, 'cb': 1}
```

## 5. restore() — roundtrip exact (mode tag)

Le roundtrip est exact : la souveraineté sur les données reste chez le client, le moteur ne stocke rien, ne voit le sel qu'en mode `hash`.

```text
original    : Facture pour société SIREN 552100554, email compta@acme.fr
restauré    : Facture pour société SIREN 552100554, email compta@acme.fr
```

## 6. v1.2 — NIR DOM (971) et corse minuscule détectés

v1.2 : la capture NIR lâche détecte les DOM (département 971-976 à 3 chiffres) et la Corse en minuscules (`2a`). La clé 97 reste le juge final.

```text
masked_text : Guadeloupe [NIR_1], Corse [NIR_2]
entities    : {'nir': 2}
```

---

## Limites assumées (dites, pas cachées)

- Tout run de 13-19 chiffres **Luhn-valide** est traité comme une carte bancaire :
  un IMEI ou numéro de série peut être masqué en `CB`. Allowlistez-le.
- Hash = HMAC-SHA3-512 complet, 128 hex (v1.3) = **corrélation déterministe**,
  pas anonymisation cryptographique (un espace d'entrée petit reste
  énumérable si le sel fuit — le sel ne quitte jamais le client).
- Détection des personnes physiques : heuristique à dictionnaire, coverage 60-70 %.
- Couche B (suspicions) : signalée, **jamais décidée seule**.

## Positionnement

Mode `tag`/`hash` = **pseudonymisation** (RGPD art. 4 — données personnelles,
le mapping/sel restant côté client). Mode `anonymize` = irréversible par
construction. Ce dépôt ne constitue pas un conseil juridique.

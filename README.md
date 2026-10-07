# OCCULTEUR v1.2 (ex-Le Confesseur)

## ⚠️ AVERTISSEMENT LÉGAL (RGPD / LOI INFORMATIQUE ET LIBERTÉS)
CE LOGICIEL EST UN OUTIL TECHNIQUE EXPÉRIMENTAL.
- **Il ne garantit PAS la conformité RGPD** ou toute autre réglementation.
- **L’auteur ne peut être tenu responsable** en cas de fuite de données, même partielle.
- **À utiliser UNIQUEMENT en environnement isolé** (ex: sandbox interne, pas en production).
- **Toute utilisation en production doit faire l’objet d’un audit juridique et technique indépendant**.

Phases de test avant déploiement.

**Moteur de pseudonymisation / anonymisation de PII françaises dans du texte libre.**
Stdlib only. Déterministe byte-for-byte. Zéro état serveur. Aucun appel réseau.

```bash
python api.py                # serveur local http://127.0.0.1:8787 (stdlib only)
python test_occulteur.py     # 59/59 specs v1.1 + v1.2
python test_confesseur.py    # 30/30 specs v1.0 (non-régression via shim)
python test_occulteur_api.py # 17/17 specs couche API
python examples.py           # vitrine exécutable -> voir EXAMPLES.md
```

![tests](https://github.com/19algorythms/occulteur-api/actions/workflows/tests.yml/badge.svg)

## L'écosystème Forge

Cet outil est l'API #2 de la Forge. Combinée à la première, elle forme une
couche de protection en entrée et en sortie :

- **[skill-to-humans](https://rapidapi.com/19algorythms/api/skill-to-humans)**
  (API #1) — *comprendre ce qu'on reçoit* : révèle le contenu caché des
  skills et prompts (manœuvres d'injection, fausses URL, fausses adresses).
- **OCCULTEUR** (API #2) — *protéger ce qu'on envoie et ce qui revient* :
  masque les PII avant l'appel au LLM (`mask`), audite la réponse avant de
  la livrer (`scan`).

L'une lit ce qui entre. L'autre verrouille ce qui sort.

## Ce que fait l'outil

Pipeline en deux couches sur du texte libre (logs, tickets, réponses de LLM) :

- **Couche A — certitude** : entité dont le checksum est valide (NIR clé 97,
  RIB/IBAN mod 97, CB/SIREN/SIRET Luhn) → masquage automatique.
- **Couche B — suspicion** : signaux faibles (CB mal recopiée, numéro proche
  d'un téléphone, email avec @ oublié) → **signalés dans le rapport avec un
  code, une raison lisible et une confiance. Jamais décidés seuls.**

Trois modes de sortie :

| Mode | Jetons | Mapping | Réversible |
|---|---|---|---|
| `tag` | `[EMAIL_1]`… | retourné côté client | oui (`restore`) |
| `hash` | `h:<hmac-48bits>` | retourné côté client | oui (sel client) |
| `anonymize` | `[EMAIL_1]`… | **jamais produit** | **non, par construction** |

Le mapping et le sel ne quittent jamais le client. Le moteur ne stocke rien,
n'a pas d'état, et est déterministe byte-for-byte (même entrée → même sortie).

## API

### `mask(text, mode="tag", salt=None, detect_secrets=True, entities=None, allowlist=None, profile="strict")`

Retourne `masked_text`, le `report` complet (entités, détails avec positions,
suspicions, compteurs allowlist), le `mapping` (sauf en `anonymize`),
`limits.usage_note`, `version`.

### `scan(text, ...)` — contrôle sortant *(nouveauté v1.1)*

Entrée identique à `mask` ; sortie = le `report` complet, **sans `masked_text`,
sans `mapping`**. Usages : audit de logs, contrôle de la réponse d'un LLM
avant envoi, étape CI `pii-check`.

### `restore(masked_text, mapping)`

Roundtrip exact en mode `tag`/`hash`. Refuse un mapping nul (mode `anonymize`)
et crie si des jetons sont présents avec un mapping vide.

### Options

- **`allowlist`** : chaînes exactes ou motifs `regex:`. Un signal allowlisté
  est ignoré partout (Couche A et B) et compté dans `report.allowlisted`
  (+ `allowlisted_breakdown` par type).
- **`profile="lenient"`** : auto-allowliste les fixtures publiques documentées
  (RFC 2606/6761, PAN de test, plage 01 99 XX XX XX). **Une vraie CB
  Luhn-valide hors liste reste masquée** — spec `t_allowlist_lenient_safe`.
- **`entities`** : filtre les familles détectées — findings **et** suspicions.

Entités couvertes : NIR (métropole, Corse 2A/2B, DOM 971-976, sexes 3/4/7/8,
mois étendus), RIB, IBAN FR, téléphones FR (0X et +33/0033), emails,
CB/SIREN/SIRET (Luhn), secrets (OpenAI, Stripe, GitHub, Slack, AWS, JWT),
mots de passe, URL avec identifiants.

## Intégration : le proxy de périmètre

Le cas d'usage cible : interposer l'OCCULTEUR entre les employés et le LLM,
**à l'intérieur du périmètre de l'entreprise** — automatiquement, à chaque
prompt, sans action manuelle.

```text
employé ──► proxy interne ──► mask() ──► LLM ──► scan() ──► employé
                ▲                                          │
                └──── mapping conservé côté proxy ◄────────┘
```

- **Le texte brut ne quitte jamais l'infra interne.** Seul le texte masqué
  part vers le LLM ; le mapping reste dans le proxy, sous le contrôle de
  l'entreprise.
- **Rapide** : ~73 ms pour un document de 50 000 caractères (benchmark v1.1)
  — l'interposition est transparente pour l'utilisateur.
- **Deux politiques** : mode `tag` (mapping conservé, restauration possible
  après audit) ou `anonymize` (irréversible, pour les flux sans besoin de
  restauration).
- **Brique exécutable fournie** : `api.py` lance le même serveur en local,
  stdlib only — point d'insertion naturel derrière le proxy.

C'est un patron d'intégration documenté, pas une boîte noire : le moteur
reste une heuristique (voir les limites ci-dessous), et une revue humaine
est recommandée avant toute restauration de données sensibles.

## Limites assumées — dites, pas cachées

- Tout run de 13-19 chiffres **Luhn-valide** est traité comme une carte
  bancaire. Un IMEI ou un numéro de série peut être masqué en `CB` :
  allowlistez-le. (Rappelé dans `usage_note` de chaque réponse.)
- Hash 48 bits = **corrélation déterministe**, pas anonymisation
  cryptographique : un espace petit (~10⁹ téléphones) reste brute-forçable
  si le sel fuit. Le sel ne quitte jamais le client.
- Détection des personnes physiques : heuristique à dictionnaire, coverage
  annoncé 60-70 %.
- Ce que le logiciel **fait** est décrit ; aucune affirmation de conformité
  réglementaire, aucune statistique marketing.

## Positionnement juridique

Définitions factuelles (art. 4 RGPD) : la **pseudonymisation** est un
traitement — les données restent personnelles, le mapping/sel étant conservé
séparément (modes `tag` et `hash`). L'information **anonyme** ne se rapporte
à aucune personne identifiable de façon irréversible (mode `anonymize`,
mapping jamais produit).

Mention SIREN : identifiant professionnel semi-public ; sur une facture, le
sensible est typiquement le RIB/IBAN, les personnes physiques, et le SIREN du
client en B2C. Terminologie : PA = plateforme agréée (ex-PDP).

Cet outil est un composant technique de traitement de texte. Il ne constitue
pas un conseil juridique et ne se substitue pas à l'analyse du responsable de
traitement. *(Bloc juridique en relecture par un conseil — voir fil de
validation avant toute affirmation commerciale de « conformité ».)*

## Sécurité

Un trou de sécurité dans ce moteur = des PII exposées. Signalez les
vulnérabilités **en privé** à l'auteur (voir `SECURITY.md`, sinon
par l'issue tracker en privé) ; ne publiez pas d'exploit avant le correctif.

## Changelog

### v1.2 (2026-10-04)

- **NIR, capture lâche** : départements DOM 971-976 (3 chiffres) et Corse
  minuscule (`2a`/`2b`) détectés ; mois `00` rejeté ; la clé 97 reste le
  juge final, un seul chemin de détection.
- **CB-KEYWORD à frontières** : `\b` autour des mots-clés — « visage » ne
  déclenche plus de suspicion carte.
- **Dates ISO silencieuses** : `2026-10-04` ne génère plus de suspicion
  parasite dans les scans de logs.
- **`entities` étendu à la Couche B** : les suspicions sont filtrées comme
  les findings.
- **`restore` verrouillé** : jetons présents + mapping vide = erreur explicite.
- Limite Luhn documentée dans `usage_note` de chaque réponse.

### v1.1 (2026-10-03)

- Allowlist (exacte + `regex:`) + profils `strict`/`lenient`.
- Endpoint `scan()` (contrôle sortant).
- Suspicion `CB-KEYWORD` (fenêtre ±60 caractères).
- Mode `anonymize` (irréversible par construction).
- NIR élargi (sexes 3/4/7/8, mois étendus) ; fix email suivi d'un point.

### v1.0 — Le Confesseur

Batterie initiale : 30 specs (checksums FR, secrets, hash déterministe,
roundtrip). Préservée verbatim — voir `test_confesseur.py` et le shim
`confesseur_engine.py`.

## Licence

**Fair Source License, v1.1 — Future Apache-2.0 License (FSL-1.1-ALv2).**
Même famille de licence que la [Forge API #1](https://rapidapi.com/19algorythms/api/skill-to-humans) — cohérence juridique de l'écosystème.

- Le code est **source-visible** : tout le monde peut lire, auditer, apprendre
  et contribuer. C'est un outil de traitement de PII : l'auditabilité n'est
  pas négociable.
- Toute **utilisation concurrente** — reprendre le moteur pour le vendre tel
  quel ou l'embarquer dans un service tiers offrant la même fonctionnalité —
  est interdite sans accord écrit de l'auteur.
- Chaque version bascule **automatiquement en Apache-2.0 deux ans après sa
  publication** (par version) — avec sa grant de brevets explicite. Le passé
  devient libre, le présent reste défendu.

Collez le texte canonique de la licence dans `LICENSE` :
https://fsl-license.org/ (FSL-1.1-ALv2). En cas de divergence, le texte
canonique prévaut. Le nom « OCCULTEUR » et « Cathédrale1995 » sont des
marques de l'auteur : la licence couvre le code, pas la marque.

## Auteurs

Conçu et forgé par **Architecte1995** (Antoine Couet), avec **Kimi K 2.6 Thinking** et **K3** (Moonshot AI)
Premier audit par mistral-medium-3-5 (Mistral AI).

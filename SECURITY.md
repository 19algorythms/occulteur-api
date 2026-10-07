# Security Policy

## Signaler une vulnérabilité

Ce moteur traite des PII : une faille ici expose des données de personnes.
Les signalements sont donc traités comme sensibles.

- **En privé uniquement** : via le [private vulnerability reporting]
  de GitHub (onglet Security → Report a vulnerability) ou l'issue tracker
  en mode privé. Ne publiez aucun détail public avant correction.
- Incluez : version concernée, entrée minimale qui déclenche le problème,
  impact estimé. **N'incluez jamais de vraies PII** dans le rapport —
  des fixtures synthétiques suffisent toujours.
- Ne testez que sur vos propres instances.

## Engagements

- Premier retour **sous les meilleurs délais** (pas d'engagement chiffré :
  un signalement sérieux mérite une réponse réfléchie, pas une réponse rapide).
- Correctif ou contournement documenté sous **14 jours** pour les failles
  d'exposition de PII ; les failles de déni de service simples sont traitées
  par ordre de sévérité.
- Crédit public au chercheur dans le changelog, sauf demande contraire.

## Périmètre

- Moteur (`occulteur_engine.py`) et couche API (`occulteur_logic.py`).
- Le serveur local `api.py` est **sans authentification par design** :
  sa mise en face d'Internet sans garde périphérique n'est pas une
  vulnérabilité, c'est un mauvais déploiement — documenté dans son
  docstring.
## ⚠️ Limitations connues
   Limitation | Impact | Solution |
 |------------|--------|----------|
 | Faux positifs CB (IMEI, numéros de série) | Données non-PII masquées | Allowlister les numéros internes |
 | Détection basée sur des heuristiques | Faux négatifs possibles | Combiner avec d'autres outils |
 | Pas de support pour les PDFs/images | PII non détectées | Utiliser un OCR en amont |
 | Déterminisme dépend de Python 3.11 | Résultats différents entre versions | Figes la version de Python |
 | `mode=hash` réversible si le sel fuit | Risque de ré-identification | Garder le sel secret |

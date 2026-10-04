"""Compatibilité ascendante : Le Confesseur v1.0 -> OCCULTEUR v1.1.
Permet à l'ancienne batterie test_confesseur.py de tourner sans modification."""
from occulteur_engine import *  # noqa: F401,F403
from occulteur_engine import (mask, restore, scan, luhn_ok, compute_nir_key,  # noqa: F401
                              rib_key, iban_ok, MAX_CHARS, VERSION)

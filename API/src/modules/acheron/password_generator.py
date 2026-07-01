"""Generador de contraseñas aleatorias seguras.

Utilidad sin estado: no depende de vaults, usuarios ni base de datos.
Usa `secrets` (CSPRNG) para toda la aleatoriedad, igual que el resto
de generación de secretos en la API (ver users/managers.py).
"""

import secrets
import string

_AMBIGUOUS = set("0O1lI")
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length: int,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
) -> str:
    pools = []
    if uppercase:
        pools.append(string.ascii_uppercase)
    if lowercase:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(_SYMBOLS)

    if exclude_ambiguous:
        pools = ["".join(c for c in pool if c not in _AMBIGUOUS) for pool in pools]

    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

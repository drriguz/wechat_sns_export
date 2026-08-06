from __future__ import annotations

"""Crockford Base32, byte-exact match of cryptowl's CrockfordBase32.kt.

Alphabet "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; output is grouped in blocks of
5 characters separated by hyphens (no '=' padding); decoding ignores hyphens
and case, and accepts the aliases I/L -> 1, O -> 0.
"""

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ALIASES = {"I": "1", "L": "1", "O": "0"}
_GROUPS = 5


def encode(data: bytes) -> str:
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | (byte & 0xFF)
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(buffer >> bits) & 0x1F])
    if bits > 0:
        out.append(ALPHABET[(buffer << (5 - bits)) & 0x1F])
    chars = "".join(out)
    return "-".join(chars[i:i + _GROUPS] for i in range(0, len(chars), _GROUPS))


def decode(encoded: str) -> bytes:
    out = bytearray()
    buffer = 0
    bits = 0
    for c in encoded:
        if c == "-":
            continue
        value = _char_value(c)
        buffer = (buffer << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


def _char_value(c: str) -> int:
    upper = c.upper()
    normalized = _ALIASES.get(upper, upper)
    index = ALPHABET.find(normalized)
    if index < 0:
        raise ValueError(f"Invalid Crockford Base32 character: {c}")
    return index

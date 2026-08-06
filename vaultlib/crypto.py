from __future__ import annotations

"""Crypto primitives, byte-exact match of the cryptowl Android implementation.

Reference implementations:
  * Argon2.kt          (phc-winner-argon2 via JNI, Argon2id, m=19456, t=2, p=1)
  * crypto/Hkdf.kt     (RFC 5869 HKDF-SHA256)
  * crypto/HmacSha256.kt
  * crypto/AesGcm.kt   (AES-256-GCM, 12 B nonce, 16 B tag, AAD support)
"""

import hashlib
import hmac

from Crypto.Cipher import AES

from argon2.low_level import Type, hash_secret_raw

# Design defaults (docs/design.md): Argon2id m=19 MiB (19456 KiB), t=2, p=1
ARGON2_M_KIB = 19456
ARGON2_T = 2
ARGON2_P = 1
HASH_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes = b"", info: bytes = b"",
                length: int = 64) -> bytes:
    """RFC 5869 HKDF-SHA256. Empty salt -> 32 zero bytes (matches Hkdf.kt)."""
    effective_salt = salt or bytes(HASH_LEN)
    prk = hmac_sha256(effective_salt, ikm)
    result = b""
    t = b""
    counter = 1
    while len(result) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        result += t
        counter += 1
    return result[:length]


def argon2id_raw(password: bytes, salt: bytes, m_kib: int = ARGON2_M_KIB,
                 t: int = ARGON2_T, p: int = ARGON2_P,
                 hash_len: int = HASH_LEN) -> bytes:
    """Argon2id raw hash bytes (matches Argon2.hash(..., type=ARGON2id))."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=hash_len,
        type=Type.ID,
    )


def aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes,
                    plaintext: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, auth_tag) — matches AesGcm.AuthEncryptedData."""
    if len(key) != HASH_LEN:
        raise ValueError(f"key must be {HASH_LEN} bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                    ciphertext: bytes, tag: bytes) -> bytes:
    """Raises ValueError on authentication failure (matches AEADBadTag)."""
    if len(key) != HASH_LEN:
        raise ValueError(f"key must be {HASH_LEN} bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

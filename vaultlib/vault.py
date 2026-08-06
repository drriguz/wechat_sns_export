from __future__ import annotations

"""Cryptowl vault — desktop reference implementation of docs/design.md.

Key hierarchy (design.md, byte-exact with the Android plan):

    P    = HMAC-SHA256(key=DeviceSecret, msg=MasterPassword)
    TMK  = Argon2id(P, salt=argon2Salt, m=19456 KiB, t=2, p=1)        (32 B)
    SMK  = HKDF-SHA256(ikm=TMK, salt=hkdfSalt, info=vaultId, L=64)
    SMK[0:32]  --AES-256-GCM(AAD="vault_key:smk")--> unwraps VaultKey
    SMK[32:64] = MAC key: verifies config.sig and vault.meta.mac
    VaultKey   = SQLCipher RAW KEY of vault.db (32 B, never plaintext)
    FEK        = HKDF-SHA256(ikm=VaultKey, salt="", info="file", L=32)
                 (C-tier file encryption key, design.md §File Encryption)

Device Secret on desktop: the design stores it in Android Keystore
(non-exportable). The desktop analog is a 32-byte secret file
`<vault>/device_secret` (mode 600). When a desktop-created vault is moved to
Android, the Android app must re-bind it once (unwrap vault_key:smk with the
desktop SMK, re-wrap with the Android SMK, delete the file) — the design's
"re-bind on import" flow.
"""

import hashlib
import hmac
import json
import os
import secrets
import tempfile

from . import crockford32
from .crypto import (ARGON2_M_KIB, aes_gcm_decrypt, aes_gcm_encrypt,
                     argon2id_raw, hkdf_sha256, hmac_sha256)
from .sqlcipher_db import SqlCipherConnection

META_VERSION = 2
SALT_LEN = 32
DEVICE_SECRET_LEN = 32
WRAPPED_KEY_ID = "vault_key:smk"

KDF_DEFAULTS = {"algorithm": "argon2id", "m_kib": ARGON2_M_KIB, "t": 2, "p": 1}

_EMPTY_SALT = bytes(SALT_LEN)


def _derive_keys(device_secret: bytes, master_password: bytes,
                 vault_id: str, meta: dict):
    """P -> TMK -> SMK; returns (tmk, smk)."""
    p = hmac_sha256(device_secret, master_password)
    argon2_salt = crockford32.decode(meta["salts"]["argon2"])
    hkdf_salt = crockford32.decode(meta["salts"]["hkdf"])
    kdf = meta["kdf"]
    tmk = argon2id_raw(p, argon2_salt, m_kib=kdf["m_kib"], t=kdf["t"],
                       p=kdf["p"], hash_len=32)
    smk = hkdf_sha256(tmk, hkdf_salt, vault_id.encode("utf-8"), 64)
    return tmk, smk


def _canonical_json(obj: dict) -> bytes:
    """Canonical JSON: lexicographic key order, compact separators
    (design.md vault.meta rules: 'canonical JSON (lexicographic key order)')."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _meta_without_mac(meta: dict) -> dict:
    return {k: v for k, v in meta.items() if k != "mac"}


class Vault:
    """An opened (or freshly created) cryptowl vault."""

    def __init__(self, path: str, meta: dict, config: dict,
                 vault_key: bytes, conn: SqlCipherConnection):
        self.path = path
        self.meta = meta
        self.config = config
        self.vault_key = vault_key
        self.conn = conn

    # ------------------------------------------------------------------ paths

    @property
    def vault_id(self) -> str:
        return self.meta["vault_id"]

    @property
    def attachments_dir(self) -> str:
        return os.path.join(self.path, "attachments")

    @property
    def thumbnails_dir(self) -> str:
        return os.path.join(self.path, "thumbnails")

    @property
    def db_path(self) -> str:
        return os.path.join(self.path, "vault.db")

    # ------------------------------------------------------------------ keys

    @property
    def file_encryption_key(self) -> bytes:
        """FEK = HKDF-SHA256(VaultKey, salt="", info="file", L=32)."""
        return hkdf_sha256(self.vault_key, b"", b"file", 32)

    # ------------------------------------------------------------ operations

    def ensure_dirs(self) -> None:
        for d in (self.attachments_dir, self.thumbnails_dir):
            os.makedirs(d, exist_ok=True)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ open

    @staticmethod
    def open(path: str, master_password: bytes,
             device_secret: bytes | None = None) -> "Vault":
        """Open a vault: verify integrity, unwrap VaultKey, open the DB.

        `device_secret` overrides the `<vault>/device_secret` file (Android
        Keystore analog is out of scope on desktop).
        """
        meta_path = os.path.join(path, "vault.meta")
        if not os.path.isfile(meta_path):
            raise FileNotFoundError(f"not a vault (no vault.meta): {path}")
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("version", 0) > META_VERSION:
            raise ValueError(
                f"vault.meta version {meta['version']} > supported {META_VERSION}")

        vault_id = meta["vault_id"]
        dir_id = os.path.basename(os.path.normpath(path))
        if vault_id != dir_id:
            print(f"[!] vault_id '{vault_id}' != directory name '{dir_id}'")

        device_secret = device_secret or _read_device_secret(path)
        _, smk = _derive_keys(device_secret, master_password, vault_id, meta)

        # config integrity (MAC key = SMK[32:64])
        config = _load_and_verify_config(path, smk[32:64])

        # vault.meta mac (over canonical JSON without the mac field)
        _verify_meta_mac(meta, smk[32:64])

        # unwrap VaultKey with SMK[0:32]
        vault_key = _unwrap_vault_key(meta, smk)

        # open the SQLCipher database with the raw key
        conn = SqlCipherConnection(os.path.join(path, "vault.db"))
        conn.key(vault_key)
        if not conn.verify_key():
            conn.close()
            raise ValueError(
                "wrong master password or corrupt database (key verification failed)")
        return Vault(path, meta, config, vault_key, conn)

    # ---------------------------------------------------------------- create

    @staticmethod
    def create(path: str, master_password: bytes,
               vault_id: str | None = None, name: str | None = None) -> "Vault":
        """Create a new vault per design.md, then verify it by reopening."""
        os.makedirs(path, exist_ok=True)
        vault_id = vault_id or os.path.basename(os.path.normpath(path))
        name = name or vault_id

        device_secret = secrets.token_bytes(DEVICE_SECRET_LEN)
        _write_device_secret(path, device_secret)

        argon2_salt = secrets.token_bytes(SALT_LEN)
        hkdf_salt = secrets.token_bytes(SALT_LEN)
        meta = {
            "version": META_VERSION,
            "vault_id": vault_id,
            "created_at": _now_ms(),
            "updated_at": _now_ms(),
            "kdf": dict(KDF_DEFAULTS),
            "salts": {
                "argon2": crockford32.encode(argon2_salt),
                "hkdf": crockford32.encode(hkdf_salt),
            },
            "wrapped_keys": [],
        }

        _, smk = _derive_keys(device_secret, master_password, vault_id, meta)

        # config.json + config.sig (written before vault.meta per design order)
        config = {"name": name}
        config_bytes = _canonical_json(config)
        config_sig = hmac_sha256(smk[32:64], config_bytes)
        _atomic_write(os.path.join(path, "config.json"), config_bytes)
        _atomic_write(os.path.join(path, "config.sig"),
                      crockford32.encode(config_sig).encode("ascii"))

        # wrap VaultKey with SMK[0:32], AAD = wrapped-key id
        vault_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ct, tag = aes_gcm_encrypt(smk[:32], nonce, WRAPPED_KEY_ID.encode("ascii"),
                                  vault_key)
        meta["wrapped_keys"].append({
            "id": WRAPPED_KEY_ID,
            "role": "vault_key",
            "wrapper": "smk",
            "algorithm": "AES-256-GCM",
            "ciphertext": crockford32.encode(ct),
            "nonce": crockford32.encode(nonce),
            "auth_tag": crockford32.encode(tag),
        })
        meta["updated_at"] = _now_ms()
        meta["mac"] = {"algorithm": "HMAC-SHA256",
                       "value": crockford32.encode(
                           hmac_sha256(smk[32:64], _canonical_json(_meta_without_mac(meta))))}
        _atomic_write(os.path.join(path, "vault.meta"),
                      _canonical_json(meta))

        # create the SQLCipher database with the raw key + core schema
        db_path = os.path.join(path, "vault.db")
        if os.path.exists(db_path):
            raise FileExistsError(
                f"vault.db already exists in '{path}' — refusing to clobber an "
                "existing vault (remove it first or use a fresh directory)")
        conn = SqlCipherConnection(db_path, raw_key=vault_key, create=True)
        try:
            if not conn.verify_key():
                raise ValueError("vault.db raw-key verification failed")
            _exec_core_schema(conn)
        finally:
            conn.close()

        # reopen to verify the whole chain end-to-end
        return Vault.open(path, master_password, device_secret)


# --------------------------------------------------------------------- helpers

def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _atomic_write(path: str, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _read_device_secret(path: str) -> bytes:
    secret_path = os.path.join(path, "device_secret")
    if not os.path.isfile(secret_path):
        raise FileNotFoundError(
            f"no device_secret for vault '{path}' — on Android this lives in "
            "Keystore; pass --device-secret or the file is missing")
    with open(secret_path, encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())


def _write_device_secret(path: str, secret: bytes) -> None:
    secret_path = os.path.join(path, "device_secret")
    _atomic_write(secret_path, secret.hex().encode("ascii"))
    os.chmod(secret_path, 0o600)


def _load_and_verify_config(path: str, mac_key: bytes) -> dict:
    config_path = os.path.join(path, "config.json")
    sig_path = os.path.join(path, "config.sig")
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"missing config.json in vault '{path}'")
    with open(config_path, "rb") as f:
        config_bytes = f.read()
    expected = hmac_sha256(mac_key, config_bytes)
    with open(sig_path, "r", encoding="ascii") as f:
        stored = crockford32.decode(f.read())
    if not hmac.compare_digest(stored, expected):
        raise ValueError("config.sig mismatch — vault config tampered")
    return json.loads(config_bytes.decode("utf-8"))


def _verify_meta_mac(meta: dict, mac_key: bytes) -> None:
    mac = meta.get("mac")
    if not mac or mac.get("algorithm") != "HMAC-SHA256":
        raise ValueError("vault.meta missing/invalid mac")
    expected = hmac_sha256(mac_key, _canonical_json(_meta_without_mac(meta)))
    stored = crockford32.decode(mac["value"])
    if not hmac.compare_digest(stored, expected):
        raise ValueError("vault.meta mac mismatch — metadata tampered")


def _unwrap_vault_key(meta: dict, smk: bytes) -> bytes:
    for wk in meta.get("wrapped_keys", []):
        if wk.get("id") != WRAPPED_KEY_ID:
            continue
        if wk.get("wrapper") != "smk":
            raise ValueError(f"{WRAPPED_KEY_ID} must be wrapped by smk")
        return aes_gcm_decrypt(
            smk[:32],
            crockford32.decode(wk["nonce"]),
            WRAPPED_KEY_ID.encode("ascii"),
            crockford32.decode(wk["ciphertext"]),
            crockford32.decode(wk["auth_tag"]),
        )
    raise ValueError(f"no {WRAPPED_KEY_ID} wrapped key in vault.meta")


_CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS t_wrapped_key (
    id         TEXT    NOT NULL PRIMARY KEY,
    role       TEXT    NOT NULL CHECK (role IN ('kek', 'ts_kek', 'top_secret_kek')),
    wrapper    TEXT    NOT NULL CHECK (wrapper IN ('smk', 'biokey', 'ts_kek', 'kek')),
    algorithm  TEXT    NOT NULL DEFAULT 'AES-256-GCM',
    ciphertext BLOB    NOT NULL,
    nonce      BLOB    NOT NULL,
    auth_tag   BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    UNIQUE (role, wrapper)
);

CREATE TABLE IF NOT EXISTS t_data_encrypt_key (
    id         CHAR(36) NOT NULL PRIMARY KEY,
    algorithm  TEXT     NOT NULL DEFAULT 'AES-256-GCM',
    ciphertext BLOB     NOT NULL,
    nonce      BLOB     NOT NULL,
    auth_tag   BLOB     NOT NULL,
    created_at INTEGER  NOT NULL,
    updated_at INTEGER  NOT NULL
);

CREATE TABLE IF NOT EXISTS t_encrypted_data (
    id         CHAR(36) NOT NULL PRIMARY KEY,
    dek_id     CHAR(36) NOT NULL REFERENCES t_data_encrypt_key (id),
    algorithm  TEXT     NOT NULL DEFAULT 'AES-256-GCM',
    content    BLOB     NOT NULL,
    nonce      BLOB     NOT NULL,
    auth_tag   BLOB     NOT NULL,
    created_at INTEGER  NOT NULL,
    updated_at INTEGER  NOT NULL,
    deleted_at INTEGER
);

CREATE INDEX IF NOT EXISTS index_t_encrypted_data_dek_id
    ON t_encrypted_data (dek_id);

CREATE TABLE IF NOT EXISTS t_file (
    id             CHAR(36) NOT NULL PRIMARY KEY,
    dek_id         CHAR(36) REFERENCES t_data_encrypt_key (id),
    classification CHAR(1)  NOT NULL CHECK (classification IN ('C', 'S', 'T')),
    storage_name   TEXT     NOT NULL,
    original_name  TEXT,
    mime_type      TEXT,
    size_bytes     INTEGER  NOT NULL,
    created_at     INTEGER  NOT NULL,
    updated_at     INTEGER  NOT NULL,
    deleted_at     INTEGER
);

CREATE INDEX IF NOT EXISTS index_t_file_dek_id ON t_file (dek_id);
CREATE INDEX IF NOT EXISTS index_t_file_classification ON t_file (classification);
"""


def _exec_core_schema(conn: SqlCipherConnection) -> None:
    conn.exec_("PRAGMA foreign_keys = ON;")
    conn.exec_("PRAGMA secure_delete = ON;")
    conn.exec_(_CORE_SCHEMA)

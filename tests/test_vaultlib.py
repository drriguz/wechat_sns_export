"""Known-answer vectors + vault lifecycle tests.

The constant vectors in this file are the cross-verification contract with
the Android implementation: run the same fixed inputs through
Argon2.kt / Hkdf.kt / HmacSha256.kt / AesGcm.kt / CrockfordBase32.kt and the
outputs must match exactly.
"""

import json
import os
import shutil
import tempfile
import unittest

from vaultlib import crockford32
from vaultlib.crypto import (aes_gcm_decrypt, aes_gcm_encrypt, argon2id_raw,
                             hkdf_sha256, hmac_sha256)
from vaultlib.vault import Vault, WRAPPED_KEY_ID

# --------------------------------------------------------------------------
# Fixed-input vectors (cross-verification with the Android implementation)
# --------------------------------------------------------------------------

DEVICE_SECRET = b"\x11" * 32
MASTER_PASSWORD = b"correct horse battery staple"
VAULT_ID = "personal"
ARGON2_SALT = b"\x22" * 32
HKDF_SALT = b"\x33" * 32
FIXED_VAULT_KEY = b"\x44" * 32
FIXED_NONCE = b"\x55" * 12

# Computed by this reference implementation with the inputs above
VECTOR_P = "89a89e43cc75104a75d4dbcc60e7e6ed0d308e718c0f7b1bf05efaccd70c030b"
VECTOR_TMK = "9049f8f4d35de3aef703a68d656e7b777f9e1742d89455414a8fd118c3043588"
VECTOR_SMK = ("551afd2b0857e902118857a01a680b14e43ff2172950a71a5ec8ec147fcbc809"
              "0471ff96c2b5486960b6596cfe6cfb7b412b93034a7950badda783f298b2e06f")
VECTOR_META_MAC = "742da83099511ccdf75578474dbe99c9d18843b6ef1f087cb460264272f07f9e"

# RFC 5869 test case 1 (sanity of HKDF vs the public spec)
RFC5869_CASE1_OKM = ("3cb25f25faacd57a90434f64d0362f2a"
                     "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                     "34007208d5b887185865")


class TestCrockford32(unittest.TestCase):
    def test_roundtrip(self):
        for size in (1, 4, 12, 16, 32, 33):
            data = os.urandom(size)
            self.assertEqual(crockford32.decode(crockford32.encode(data)), data)

    def test_groups_of_five_with_hyphens(self):
        s = crockford32.encode(b"\x22" * 32)
        parts = s.split("-")
        self.assertTrue(all(len(p) == 5 for p in parts[:-1]))
        self.assertTrue(1 <= len(parts[-1]) <= 5)

    def test_decode_ignores_case_hyphens_and_aliases(self):
        enc = crockford32.encode(b"\x22" * 32)
        self.assertEqual(crockford32.decode(enc.lower()), b"\x22" * 32)
        self.assertEqual(crockford32.decode(enc.replace("-", "")), b"\x22" * 32)
        self.assertEqual(crockford32.decode("il1"), crockford32.decode("111"))
        self.assertEqual(crockford32.decode("o0"), crockford32.decode("00"))

    def test_invalid_character_rejected(self):
        with self.assertRaises(ValueError):
            crockford32.decode("!")


class TestCryptoVectors(unittest.TestCase):
    def test_hmac_sha256(self):
        p = hmac_sha256(DEVICE_SECRET, MASTER_PASSWORD)
        self.assertEqual(p.hex(), VECTOR_P)

    def test_argon2id(self):
        tmk = argon2id_raw(hmac_sha256(DEVICE_SECRET, MASTER_PASSWORD),
                           ARGON2_SALT, m_kib=19456, t=2, p=1)
        self.assertEqual(tmk.hex(), VECTOR_TMK)

    def test_hkdf_smk(self):
        tmk = bytes.fromhex(VECTOR_TMK)
        smk = hkdf_sha256(tmk, HKDF_SALT, VAULT_ID.encode("utf-8"), 64)
        self.assertEqual(smk.hex(), VECTOR_SMK)

    def test_hkdf_rfc5869_case1(self):
        okm = hkdf_sha256(bytes.fromhex("0b" * 22),
                          bytes.fromhex("000102030405060708090a0b0c"),
                          bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(), RFC5869_CASE1_OKM)

    def test_aes_gcm_roundtrip(self):
        key, nonce, aad = os.urandom(32), os.urandom(12), b"vault_key:smk"
        ct, tag = aes_gcm_encrypt(key, nonce, aad, b"secret data")
        self.assertEqual(aes_gcm_decrypt(key, nonce, aad, ct, tag),
                         b"secret data")
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(key, nonce, b"wrong-aad", ct, tag)


class TestVaultLifecycle(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cryptowl-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_create_open_roundtrip(self):
        path = os.path.join(self.dir, "personal")
        vault = Vault.create(path, MASTER_PASSWORD, vault_id=VAULT_ID)
        self.assertEqual(vault.vault_id, VAULT_ID)
        self.assertEqual(len(vault.vault_key), 32)
        self.assertEqual(len(vault.file_encryption_key), 32)
        vault.close()

        with Vault.open(path, MASTER_PASSWORD) as reopened:
            self.assertEqual(reopened.vault_key, vault.vault_key)
            self.assertEqual(reopened.config, {"name": VAULT_ID})

    def test_fek_is_deterministic_and_keyed_off_vault_key(self):
        path = os.path.join(self.dir, "a")
        v = Vault.create(path, MASTER_PASSWORD)
        fek1 = v.file_encryption_key
        v.close()
        with Vault.open(path, MASTER_PASSWORD) as v2:
            self.assertEqual(v2.file_encryption_key, fek1)
            # FEK != VaultKey, and stable across re-open
            self.assertNotEqual(v2.vault_key, fek1)

    def test_wrong_password_fails(self):
        path = os.path.join(self.dir, "b")
        Vault.create(path, MASTER_PASSWORD)
        with self.assertRaises(ValueError):
            Vault.open(path, b"wrong password")

    def test_tampered_config_rejected(self):
        path = os.path.join(self.dir, "c")
        Vault.create(path, MASTER_PASSWORD)
        with open(os.path.join(path, "config.json"), "a") as f:
            f.write(" ")
        with self.assertRaises(ValueError) as ctx:
            Vault.open(path, MASTER_PASSWORD)
        self.assertIn("config.sig", str(ctx.exception))

    def test_tampered_meta_rejected(self):
        path = os.path.join(self.dir, "d")
        Vault.create(path, MASTER_PASSWORD)
        with open(os.path.join(path, "vault.meta")) as f:
            meta = json.load(f)
        meta["tampered"] = True  # does not affect key derivation, so the
        # config.sig still validates and the meta mac must catch it
        with open(os.path.join(path, "vault.meta"), "w") as f:
            json.dump(meta, f, sort_keys=True, separators=(",", ":"))
        with self.assertRaises(ValueError) as ctx:
            Vault.open(path, MASTER_PASSWORD)
        self.assertIn("mac", str(ctx.exception))

    def test_moved_vault_opens(self):
        # "copy vault to local computer" flow: the vault dir is portable
        path = os.path.join(self.dir, "e")
        Vault.create(path, MASTER_PASSWORD)
        moved = os.path.join(self.dir, "moved")
        shutil.copytree(path, moved)
        with Vault.open(moved, MASTER_PASSWORD) as v:
            self.assertEqual(v.vault_id, "e")

    def test_create_refuses_existing_db(self):
        path = os.path.join(self.dir, "f")
        Vault.create(path, MASTER_PASSWORD)
        with self.assertRaises(FileExistsError):
            Vault.create(path, MASTER_PASSWORD)

    def test_db_is_sqlcipher_encrypted(self):
        path = os.path.join(self.dir, "g")
        Vault.create(path, MASTER_PASSWORD)
        header = open(os.path.join(path, "vault.db"), "rb").read(16)
        self.assertNotEqual(header, b"SQLite format 3\x00")

    def test_wrapped_key_metadata(self):
        path = os.path.join(self.dir, "h")
        Vault.create(path, MASTER_PASSWORD)
        meta = json.load(open(os.path.join(path, "vault.meta")))
        wk = meta["wrapped_keys"][0]
        self.assertEqual(wk["id"], WRAPPED_KEY_ID)
        self.assertEqual(wk["role"], "vault_key")
        self.assertEqual(wk["wrapper"], "smk")
        self.assertEqual(wk["algorithm"], "AES-256-GCM")
        self.assertEqual(set(meta["salts"]), {"argon2", "hkdf"})
        self.assertEqual(meta["kdf"]["algorithm"], "argon2id")


if __name__ == "__main__":
    unittest.main()

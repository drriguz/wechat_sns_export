"""
WeChat (macOS 4.x) SQLCipher database decryptor.

Finds the WeChat db_storage directory, locates the SNS database (sns/sns.db by
default), matches its encryption key from all_keys.json, and writes a decrypted
plaintext SQLite file to a new output path.

Encryption parameters (WeChat 4.x):
    SQLCipher 4, AES-256-CBC, HMAC-SHA512, page_size=4096, reserve=80
    key = x'<enc_key_hex><db_salt_hex>'   (enc_key extracted from process memory)

Usage:
    python decrypt_db.py                      # decrypt sns/sns.db to ./decrypted/sns.db
    python decrypt_db.py --all                # decrypt every *.db under db_storage
    python decrypt_db.py message/media_0.db   # decrypt a specific db
    python decrypt_db.py --db-dir /path/to/db_storage --keys-file /path/all_keys.json
"""
import argparse
import functools
import hashlib
import hmac as hmac_mod
import json
import os
import sqlite3
import struct
import sys

from Crypto.Cipher import AES

print = functools.partial(print, flush=True)

PAGE_SZ = 4096
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
KEY_SZ = 32
SQLITE_HDR = b"SQLite format 3\x00"

DEFAULT_DB = "sns/sns.db"

DEFAULT_DB_STORAGE_BASE = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)

# Candidates for all_keys.json, in priority order. The key file is produced by
# the memory scanner in the wechat-decrypt project (find_all_keys_macos).
KEYS_CANDIDATES = [
    os.environ.get("WECHAT_DECRYPT_KEYS", ""),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "wechat-decrypt", "all_keys.json"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "all_keys.json"),
]


def _is_encrypted(db_path):
    """SQLCipher-encrypted DBs have a random 16-byte salt instead of the header."""
    try:
        with open(db_path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    return len(head) == 16 and head != SQLITE_HDR[:16]


def detect_db_storage_dir():
    """Find db_storage dirs under the WeChat container; pick the most recently used."""
    base = DEFAULT_DB_STORAGE_BASE
    if not os.path.isdir(base):
        return None
    candidates = []
    for wxid in os.listdir(base):
        storage = os.path.join(base, wxid, "db_storage")
        if os.path.isdir(storage):
            candidates.append(storage)
    if not candidates:
        return None
    candidates.sort(
        key=lambda p: os.path.getmtime(os.path.join(p, "sns"))
        if os.path.isdir(os.path.join(p, "sns")) else 0,
        reverse=True,
    )
    return candidates[0]


def load_keys(keys_file):
    if not keys_file or not os.path.isfile(keys_file):
        return None
    with open(keys_file, encoding="utf-8") as f:
        keys = json.load(f)
    return {k: v for k, v in keys.items() if not k.startswith("_")}


def path_variants(rel_path):
    normalized = rel_path.replace("\\", "/")
    variants = {rel_path, normalized, normalized.replace("/", "\\")}
    return variants


def match_key_by_path(keys, rel_path):
    for v in path_variants(rel_path):
        if v in keys:
            return keys[v]
    return None


def derive_mac_key(enc_key, salt):
    """Derive the HMAC key from enc_key: PBKDF2-HMAC-SHA512 over salt XOR 0x3a."""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_page1(enc_key, page1):
    """Verify page 1 HMAC; returns True if enc_key matches this db."""
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(hm.digest(), p1_stored_hmac)


def find_key(db_path, keys):
    """Find the enc_key for db_path: exact path match first, then brute-force
    HMAC verification over all known keys (db salt is embedded in the file)."""
    with open(db_path, "rb") as f:
        page1 = f.read(PAGE_SZ)
    if len(page1) < PAGE_SZ:
        return None
    salt = page1[:SALT_SZ]
    for key_info in keys.values():
        enc_key = bytes.fromhex(key_info["enc_key"])
        if verify_page1(enc_key, page1):
            return enc_key, salt
    return None


def decrypt_page(enc_key, page_data, pgno):
    """Decrypt a single 4096-byte page into a standard SQLite page."""
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
        return bytes(bytearray(SQLITE_HDR + decrypted + b"\x00" * RESERVE_SZ))
    encrypted = page_data[: PAGE_SZ - RESERVE_SZ]
    decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
    return decrypted + b"\x00" * RESERVE_SZ


def decrypt_database(db_path, out_path, enc_key):
    """Decrypt the whole file page by page; returns True on success."""
    file_size = os.path.getsize(db_path)
    total_pages = (file_size + PAGE_SZ - 1) // PAGE_SZ
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) == 0:
                    break
                page += b"\x00" * (PAGE_SZ - len(page))
            fout.write(decrypt_page(enc_key, page, pgno))
    return True


def collect_dbs(db_dir):
    dbs = []
    for root, dirs, files in os.walk(db_dir):
        dirs[:] = [d for d in dirs if not d.endswith(("-wal", "-shm"))]
        for f in files:
            if f.endswith(".db"):
                path = os.path.join(root, f)
                if _is_encrypted(path):
                    dbs.append((os.path.relpath(path, db_dir), path))
    dbs.sort(key=lambda t: t[0])
    return dbs


def verify_plaintext(out_path):
    """Open as plaintext SQLite and return the table list. The decrypted db may
    be in WAL journal mode, which cannot be opened read-only without an existing
    -shm index, so open read-write, checkpoint, and remove residual -wal/-shm."""
    conn = sqlite3.connect(out_path)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return tables
    finally:
        conn.close()
        for suffix in ("-wal", "-shm"):
            residual = out_path + suffix
            if os.path.exists(residual):
                try:
                    os.remove(residual)
                except OSError:
                    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="WeChat 4.x SQLCipher db decryptor")
    parser.add_argument("db", nargs="?", default=DEFAULT_DB,
                        help=f"db relative to db_storage (default: {DEFAULT_DB})")
    parser.add_argument("--db-dir", help="db_storage directory (auto-detected if omitted)")
    parser.add_argument("--keys-file", help="path to all_keys.json (auto-detected if omitted)")
    parser.add_argument("--output", help="output file path (default: ./decrypted/<name>.db)")
    parser.add_argument("--all", action="store_true", help="decrypt every .db under db_storage")
    args = parser.parse_args(argv)

    db_dir = args.db_dir or detect_db_storage_dir()
    if not db_dir or not os.path.isdir(db_dir):
        print(f"[ERROR] db_storage directory not found: {db_dir}")
        sys.exit(1)
    print(f"[+] db_storage: {db_dir}")

    keys_file = args.keys_file
    if not keys_file:
        keys_file = next((c for c in KEYS_CANDIDATES if c and os.path.isfile(c)), None)
    keys = load_keys(keys_file)
    if not keys:
        print(f"[ERROR] keys file not found: {keys_file or '(none)'}")
        print("  Run the key extractor in wechat-decrypt (find_all_keys_macos) first,")
        print("  or pass --keys-file.")
        sys.exit(1)
    print(f"[+] keys: {os.path.abspath(keys_file)} ({len(keys)} keys)")

    if args.all:
        targets = collect_dbs(db_dir)
        if not targets:
            print("[!] No encrypted .db files found")
            sys.exit(1)
    else:
        db_rel = args.db.replace("\\", "/")
        db_path = os.path.join(db_dir, db_rel)
        if not os.path.isfile(db_path):
            print(f"[ERROR] db not found: {db_path}")
            sys.exit(1)
        targets = [(db_rel, db_path)]

    print(f"\n{len(targets)} database(s) to decrypt\n")
    ok_count = fail_count = 0
    for rel, path in targets:
        out_path = args.output or os.path.join("decrypted", rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        key_info = match_key_by_path(keys, rel)
        enc_key = bytes.fromhex(key_info["enc_key"]) if key_info else None
        matched = "path" if key_info else None
        if not enc_key:
            found = find_key(path, keys)
            if found:
                enc_key, _ = found
                matched = "hmac"
        if not enc_key:
            print(f"FAIL: {rel} (no matching key in keys file)")
            fail_count += 1
            continue

        print(f"decrypt: {rel} ({os.path.getsize(path)/1024/1024:.1f} MB, key={matched}) ...", end=" ")
        try:
            decrypt_database(path, out_path, enc_key)
            tables = verify_plaintext(out_path)
            print(f"OK -> {out_path} ({len(tables)} tables: {', '.join(tables[:6])}{'...' if len(tables) > 6 else ''})")
            ok_count += 1
        except Exception as e:
            print(f"FAIL: {e}")
            fail_count += 1

    print(f"\nDone: {ok_count} ok, {fail_count} failed")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    main()

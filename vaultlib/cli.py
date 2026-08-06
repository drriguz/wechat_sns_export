from __future__ import annotations

"""CLI for the cryptowl vault tool: create / info / verify.

Usage:
    python -m vaultlib create <vault-dir> [--vault-id id] [--name n]
                              [--password pw | --password-file f]
    python -m vaultlib info <vault-dir> [--password pw | --password-file f]
    python -m vaultlib verify <vault-dir> [--password pw | --password-file f]
"""

import argparse
import json
import os
import sys

from .crypto import ARGON2_M_KIB
from .vault import META_VERSION, Vault


def _password(args) -> bytes:
    if getattr(args, "password", None):
        return args.password.encode("utf-8")
    if getattr(args, "password_file", None):
        return open(args.password_file, "rb").read().strip()
    raise SystemExit("missing password: use --password or --password-file")


def _cmd_create(args) -> int:
    vault = Vault.create(args.vault_dir, _password(args),
                         vault_id=args.vault_id, name=args.name)
    print(f"[+] vault created: {vault.path}")
    print(f"    vault_id : {vault.vault_id}")
    print(f"    kdf      : argon2id m={ARGON2_M_KIB}KiB t=2 p=1")
    print(f"    db       : {vault.db_path}")
    print("[+] reopen/verify: OK (mac, config.sig, wrapped key, SQLCipher raw key)")
    print("[!] device_secret file created (desktop analog of Android Keystore)")
    vault.close()
    return 0


def _cmd_info(args) -> int:
    password = _password(args) if args.password or args.password_file else None
    if password is None:
        _structural_info(args.vault_dir)
        print("[i] pass --password for full verification + DB contents")
        return 0
    vault = Vault.open(args.vault_dir, password)
    print(f"vault_id      : {vault.vault_id}")
    print(f"config        : {json.dumps(vault.config, ensure_ascii=False)}")
    print(f"config.sig    : valid (MAC key)")
    print(f"vault.meta mac: valid")
    print(f"wrapped keys  : {[w['id'] for w in vault.meta['wrapped_keys']]}")
    print(f"vault_key     : {vault.vault_key.hex()}")
    print(f"FEK           : {vault.file_encryption_key.hex()}")
    print(f"SQLCipher     : raw-key verified, tables:")
    for table in vault.conn.tables():
        print(f"    {table:24s} {vault.conn.row_count(table):>8d} rows")
    vault.close()
    return 0


def _structural_info(path: str) -> None:
    meta_path = os.path.join(path, "vault.meta")
    if not os.path.isfile(meta_path):
        raise SystemExit(f"not a vault (no vault.meta): {path}")
    meta = json.load(open(meta_path, encoding="utf-8"))
    print(f"version       : {meta.get('version')} (max supported {META_VERSION})")
    print(f"vault_id      : {meta.get('vault_id')}")
    print(f"kdf           : {meta.get('kdf')}")
    print(f"salts         : argon2={meta['salts']['argon2']} "
          f"hkdf={meta['salts']['hkdf']}")
    print(f"wrapped keys  : {[w['id'] for w in meta.get('wrapped_keys', [])]}")
    print(f"config        : {open(os.path.join(path, 'config.json')).read().strip()}"
          if os.path.isfile(os.path.join(path, "config.json")) else "config: missing")
    for f in ("vault.db", "device_secret"):
        p = os.path.join(path, f)
        print(f"{f:15s}: {'present' if os.path.isfile(p) else 'MISSING'}")


def _cmd_verify(args) -> int:
    password = _password(args)
    with Vault.open(args.vault_dir, password) as vault:
        print(f"[+] vault OK: {vault.vault_id} (mac + config.sig + wrapped key "
              f"+ SQLCipher raw key verified)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vaultlib", description="cryptowl vault tool (desktop reference impl)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="create a new vault")
    p_create.add_argument("vault_dir")
    p_create.add_argument("--vault-id", help="vault identity (default: dir name)")
    p_create.add_argument("--name", help="display name (default: vault-id)")
    p_create.add_argument("--password")
    p_create.add_argument("--password-file", type=argparse.FileType("rb"))
    p_create.set_defaults(func=_cmd_create)

    for name in ("info", "verify"):
        p = sub.add_parser(name, help=f"{name} a vault")
        p.add_argument("vault_dir")
        p.add_argument("--password")
        p.add_argument("--password-file", type=argparse.FileType("rb"))
        p.set_defaults(func=_cmd_info if name == "info" else _cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

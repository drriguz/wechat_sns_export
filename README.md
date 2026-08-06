# wechat_sns_export

Export WeChat (macOS 4.x) SNS / Moments data. Step 1: decrypt the SQLCipher-encrypted
WeChat databases into plain SQLite files.

## Overview

WeChat 4.x stores its data in SQLCipher-encrypted SQLite databases under:

```
~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage/
    ├── sns/        sns.db            <- Moments (朋友圈) data
    ├── message/    message_*.db, weclaw.db, media_*.db
    ├── contact/    contact.db, contact_fts.db
    ├── session/    session.db
    └── ...         (18 databases total in this account)
```

`decrypt_db.py` decrypts these databases and writes plaintext SQLite files into
`decrypted/<rel/path>.db` (by default `decrypted/sns/sns.db` for the SNS database).

## Requirements

- Python 3.9+
- [pycryptodome](https://pypi.org/project/pycryptodome/) (`Crypto` module) — AES
- [Node.js](https://nodejs.org) — drives WeChat's official WASM module for the
  SNS media keystream (Step 4)
- An `all_keys.json` file containing the per-database encryption keys (see below)

```bash
python3 -m venv .venv
.venv/bin/pip install pycryptodome
```

## Usage

```bash
.venv/bin/python decrypt_db.py                        # sns/sns.db -> decrypted/sns/sns.db
.venv/bin/python decrypt_db.py --all                  # every *.db under db_storage
.venv/bin/python decrypt_db.py message/message_0.db   # a specific database
.venv/bin/python decrypt_db.py --db-dir /custom/path/db_storage \
                              --keys-file /custom/all_keys.json \
                              --output out.db
```

Output for the default run:

```
[+] db_storage: /Users/.../xwechat_files/wxid_0974339742812_a2f7/db_storage
[+] keys: /Users/.../wechat-decrypt/all_keys.json (18 keys)
decrypt: sns/sns.db (18.7 MB, key=path) ... OK -> decrypted/sns/sns.db (13 tables: SnsAdTimeLine, SnsDraft, ...)
```

Each decrypted file is verified by opening it with `sqlite3` and listing tables;
residual `-wal`/`-shm` files created during verification are removed.

## Step 2: export SNS data to JSON

```bash
.venv/bin/python export_sns.py                        # decrypted/sns/sns.db -> decrypted/sns_export.json
.venv/bin/python export_sns.py --only-mine            # only posts authored by your account
.venv/bin/python export_sns.py --db path/sns.db --output out.json
.venv/bin/python export_sns.py --no-raw               # omit raw_xml, --no-aux omits auxiliary tables
```

The output goes to `decrypted/sns_export.json` (the whole `decrypted/` folder is
git-ignored).

`--only-mine` keeps only posts whose author is your own account: by default the
account owner is auto-detected as the most frequent author in the timeline, or
you can pin it with `--own-username <wxid>`. The downloaded timeline includes
posts from other people (e.g. shares), so use `--only-mine` for your own data
only.

The `content` column of `SnsTimeLine` is an XML document (`SnsDataItem`), not
protobuf. Each row is parsed into a structured post:

```json
{
  "tid": -3469599834754043209,          // row primary key; joins comments/likes
  "id": "14977144238955508407",         // timeline object id
  "username": "wxid_...", "nickname": "三行",
  "create_time": 1785414724, "create_time_str": "2026-07-30 20:32:04",
  "content_desc": "🎂",
  "content_type": 1, "content_type_name": "image_text",
  "is_private": false,
  "location": { "latitude": "...", "longitude": "...", "poi_name": "..." },
  "media": [ { "id": "...", "type": "2", "url": "http://szmmsns.qpic.cn/.../0",
               "thumb_url": "...", "width": "1440", "height": "1920", ... } ],
  "likes":    [ { "username": "...", "nickname": "...", "create_time": ... } ],
  "comments": [ { "username": "...", "nickname": "陈婷婷", "content": "好吃不",
                  "to_username": "...", "comment_id": 131, ... } ],
  "pack_info_buf": "...",               // hex of the raw buffer
  "raw_xml": "<SnsDataItem>..."         // original XML (--no-raw to drop)
}
```

Handling details:

- **Content encodings** — `content` may be zstd-compressed bytes, plain XML,
  hex, or base64 depending on WeChat version; all four are detected and decoded
  (zstd decompression requires the `zstandard` package, optional).
- **Dirty XML repair** — old posts (2013-2017) contain bare `&`, raw `< >`
  inside text nodes, and control characters that break ElementTree; these are
  repaired (CDATA blocks untouched) before parsing.
- **XXE protection** — content is untrusted input; `<!DOCTYPE` / `<!ENTITY`
  payloads are rejected.
- **Comments/likes** — `SnsMessage_tmp3` rows are joined to posts via
  `feed_id` = `tid`; withdrawn interactions (`del_status != 0`) are skipped.
- **Binary columns** — `pack_info_buf` is TEXT-typed but holds binary junk, so
  it is read with `hex()` and a lenient `text_factory`.

Output JSON shape: `exported_at`, `statistics`, `posts[]`, and
`auxiliary_tables` (non-empty auxiliary tables such as `SnsAdTimeLine` ads and
`SnsTopItem_1`).

Result on this machine: 2548 posts in the db (2418 authored by the account
owner), 0 parse failures. With `--only-mine`: 2418 posts, 3279 media items, 97
posts with location, 22 comments/likes joined from `SnsMessage_tmp3`.

## Step 3: download media from the CDN

> Run `export_sns.py --only-mine` first so only your own media is downloaded.

```bash
.venv/bin/python download_media.py                          # full run, 4 workers
.venv/bin/python download_media.py --workers 8 --force      # re-download everything
.venv/bin/python download_media.py --json path.json --output dir --no-thumbs
```

Reads the media URLs from `decrypted/sns_export.json`, downloads each full file
and its thumbnail from the WeChat CDN (`mmsns.qpic.cn`), and stores them in
`decrypted/media_cdn/`:

```
decrypted/media_cdn/
    <media_id>.enc          full-size file (raw CDN bytes, kept encrypted)
    <media_id>_t.enc        thumbnail
    download_manifest.json  per-file record
```

Key behavior:

- **Kept encrypted** — CDN content is stream-encrypted by WeChat (`enc_idx=1`,
  no known header/magic, custom scheme); files are saved byte-for-byte as
  `.enc` and never altered.
- **URL construction** — `http://` is upgraded to `https://` and `token=<token>&idx=1`
  is appended; the token is mandatory (any other value of `idx`, or no token,
  returns HTTP 400).
- **Caching / resume** — existing non-empty files are skipped; the manifest is
  rewritten incrementally, so interrupted runs can be restarted safely.
- **Retries** — 3 attempts with backoff, 30 s timeout, `MicroMessenger Client`
  user agent.
- **Checksums** — the XML carries `url_md5`, but for encrypted content that is
  the md5 of the *decrypted* bytes, so those entries are marked `unverifiable`
  in the manifest (actual md5 of the downloaded bytes is still recorded).
  Plain (unencrypted) files are md5-verified and marked `ok` / `mismatch`.
  Entries without an md5 are marked `n/a`.
- **Parallelism** — `--workers` (default 4) controls concurrent downloads;
  tokens expire over time (HTTP 400), so items that fail with expired tokens
  are recorded in the manifest with their error and skipped on the next run.

Manifest entry example:

```json
{
  "media_id": "14978971848469131954",
  "variant": "full",
  "status": "ok",
  "url": "http://mmsns.qpic.cn/.../0",
  "size": 130117,
  "md5": "122ba61ab9fc060b3ffe4b5548b4d2b4",
  "md5_expected": "4f7599a82dfe34ffbc8e4bb8d2cfbd2e",
  "checksum": "unverifiable",
  "saved_path": "decrypted/media_cdn/14978971848469131954.enc"
}
```

## Step 4: decrypt the CDN media

```bash
.venv/bin/python decrypt_media.py                          # full run, 8 workers
.venv/bin/python decrypt_media.py --workers 4 --force      # re-decrypt everything
```

Reads `decrypted/media_cdn/` (from Step 3) and writes plaintext media to
`decrypted/media_decrypted/`:

```
decrypted/media_decrypted/
    <media_id>.jpg / .png / .gif / .webp / .mp4 / ...
    <media_id>_t.jpg                (thumbnails)
    decrypt_manifest.json           per-file status record
```

### The CDN encryption scheme (ISAAC-64)

The `x-Enc: 1` CDN responses are encrypted with WeChat's **ISAAC-64** PRNG
(stream cipher): the media `key` seeds the PRNG and the resulting keystream is
XOR-ed over the ciphertext.

- **Images** — the *entire file* is XOR-ed; seed = the media element's `key`
  attribute (`url_key` / `thumb_key`).
- **Videos** — only the **first 131072 bytes** (128 KB) are encrypted; the seed
  comes from the post XML's top-level `<enc key="...">` tag (not the media
  element).
- **Byte order** — each 64-bit keystream word is emitted as `lo32 BE || hi32 BE`
  (the equivalent of the client's `htonl(hi32)<<32 | htonl(lo32)` byte swap).

The keystream is generated by **WeChat's official WASM module**
(`wasm_video_decode.wasm`, exposing the `WxIsaac64` class), which is downloaded
from WeChat's own CDN on first run into `decrypted/wechat_wasm/` and driven via
`isaac_keystream.mjs` (node subprocess). This guarantees byte-exact keystreams
for every WeChat version. A pure-Python ISAAC-64 port of the public reference
exists but does **not** reproduce WeChat's variant, hence the WASM.

### Validation & caching

- **Cache by file name** — an existing output file is skipped (`--force` to
  redo); the manifest is updated incrementally for resume.
- **Already-plaintext files** — the CDN sometimes returns unencrypted bytes
  despite `enc_idx=1`; those are detected by magic bytes and copied as-is.
- **md5 validation** — where the XML carries `url_md5`, the decrypted bytes'
  md5 is compared: `ok` when it matches, `mismatch` when the CDN re-encoded
  the file (WeChat stores the md5 of the original upload; some files match).
- **Format validation** — every output file must sniff to a known format
  (jpg/png/gif/webp/mp4/heic) or it is rejected.

Result on this machine: 5608/5918 decrypted (5395 jpg, 211 mp4, 2 png, ~984 MB);
208 md5 matches, 980 mismatches (re-encoded originals), 310 skipped — media
without a key in the XML (`key="0"`, thumbnails of old video posts).

## Step 5: browse it as a WeChat Moments web app

A React + TypeScript + Tailwind frontend with a Flask + SQLite backend that
renders the exported posts as a WeChat Moments (朋友圈) timeline.

```bash
# 1. ingest the JSON export into SQLite
.venv/bin/python backend/ingest.py          # -> decrypted/sns.sqlite

# 2. start the API (http://127.0.0.1:5001)
.venv/bin/python backend/app.py

# 3. start the frontend (http://localhost:5174)
cd frontend && npm install && npm run dev
```

Layout:

```
backend/
    ingest.py   JSON -> SQLite (posts, media tables; media resolved to files)
    app.py      Flask API + media file serving
frontend/       Vite + React + TS + Tailwind (WeChat Moments UI)
isaac_keystream.mjs   WASM keystream driver (used by decrypt_media.py)
```

API:

| Endpoint | Description |
|---|---|
| `GET /api/posts?page=1&page_size=10&search=kw` | paginated posts (newest first), content/nickname search |
| `GET /api/posts/<tid>` | single post |
| `GET /api/stats` | post/media counts |
| `GET /media/<file>` | decrypted media (thumbnails `*_t.jpg`) |

UI features: infinite-scroll pagination, search-as-you-type (Enter), WeChat
**Album (相册)** layout — date on the left, images on top, content below;
long text is collapsed with a 全文 (expand) toggle; link posts render as a
clickable link card; video thumbs with play icon + fullscreen lightbox
(keyboard arrows); likes/comments in the classic gray box; location pins.

## Step 6: migrate the archive into a cryptowl vault

The final destination is your own encrypted vault app (cryptowl). The desktop
tooling in this repo — `vaultlib/` — is the **reference implementation of the
cryptowl vault design** ([docs/design.md](../cryptowl/docs/design.md)):
key hierarchy (Argon2id/HKDF/HMAC/AES-256-GCM), `vault.meta` + `config.sig`,
SQLCipher raw key, and the moments feature schema
([docs/moments.md](../cryptowl/docs/moments.md)). It is byte-exact with the
Android implementation for cross-verification (fixed test vectors in
`tests/test_vaultlib.py`).

Workflow: create/borrow a vault, migrate into it, copy it back to Android.

```bash
# 1. create a vault (needs: python3 -m venv .venv; pip install -r requirements.txt)
.venv/bin/python -m vaultlib create ../vaults/personal \
    --vault-id personal --name "我的珍藏" --password <master-password>

# 2. migrate the WeChat export into it (opens the vault, verifies integrity,
#    encrypts media with FEK into attachments/ + thumbnails/, fills the DB)
.venv/bin/python migrate_moments.py --vault ../vaults/personal \
    --password <master-password> \
    --json decrypted/sns_export.json --media decrypted/media_decrypted

# 3. inspect the result
.venv/bin/python -m vaultlib info ../vaults/personal --password <master-password>
```

Result on this machine (2418 posts): 2418 moments, 1040 cards, 2780 media,
7497 comments, 6715 likes; 960 MB of FEK-encrypted `.cwo` files in
`attachments/` + 25 MB thumbnails. Re-running the migration is a no-op
(idempotent by WeChat `source_id`).

### Vault tooling

```
vaultlib/                  desktop reference implementation of the cryptowl vault
    vault.py               create/open: key derivation, vault.meta, config.sig,
                           SQLCipher raw-key connection, FEK
    crypto.py              Argon2id / HKDF-SHA256 / HMAC-SHA256 / AES-256-GCM
    crockford32.py         Crockford Base32 (byte-exact with the Android impl)
    sqlcipher_db.py        ctypes binding to libsqlcipher (brew install sqlcipher)
    cli.py                 `create` / `info` / `verify` commands
migrate_moments.py         WeChat export JSON + decrypted media -> vault
tests/                     unit + integration tests (fixed cross-verification
                           vectors for the Android implementation)
```

Notes:

- **Device Secret** — the design stores it in Android Keystore; on desktop it
  is a 32-byte `<vault>/device_secret` file (mode 600). When moving a
  desktop-created vault to Android, the app must re-bind it once (unwrap
  `vault_key:smk` with the desktop SMK, re-wrap with the Android SMK, delete
  the file) — the design's "re-bind on import" flow.
- **Media files** are encrypted with FEK = `HKDF-SHA256(VaultKey, info="file")`
  as CWO1 blobs (whole-file AES-256-GCM for images/audio, chunked 64 KiB GCM
  for video; AAD = media row id) — see [docs/moments.md](../cryptowl/docs/moments.md) §4.
- **Requirements** for the migration path: `pip install argon2-cffi
  pycryptodome` plus `brew install sqlcipher` (or set `LIBSQLCIPHER`).
  `--password-file` is supported for the master password.

## How the encryption works

### Encryption parameters (WeChat 4.x)

| Parameter     | Value                                |
|---------------|--------------------------------------|
| Cipher        | SQLCipher 4                          |
| Page size     | 4096 bytes                           |
| Cipher        | AES-256-CBC                          |
| MAC           | HMAC-SHA512                          |
| Reserve space | 80 bytes (16-byte IV + 64-byte HMAC) |
| KDF           | PBKDF2-HMAC-SHA512 (via SQLCipher)   |

The effective SQLCipher key is `x'<key_hex><salt_hex>'`: a 32-byte raw key
(extracted from WeChat process memory) concatenated with the per-database 16-byte
salt stored in the database file itself.

### On-disk page layout

Each 4096-byte page is laid out as:

```
offset 0                              offset 4016               offset 4032   offset 4096
┌─────────────────────────────────────┬────────────────────────┬─────────────────────┐
│ data (encrypted with AES-256-CBC)   │ IV (16 bytes)          │ HMAC-SHA512 (64)    │
└─────────────────────────────────────┴────────────────────────┴─────────────────────┘
```

Exceptions:

- **Page 1**: the first 16 bytes are the plaintext salt (not the usual `SQLite
  format 3\0` header). The encrypted region is `[16, 4016)`.
- **HMAC data**: covers the encrypted region plus the IV; for page 1 that is
  bytes `[16, 4032)`. The 32-bit page number is appended to the input before
  hashing, and the result is compared against the last 64 bytes.

### Key derivation (HMAC key)

The HMAC key is derived from the raw key and salt:

```
mac_key = PBKDF2-HMAC-SHA512(password=enc_key, salt=(db_salt XOR 0x3a), iterations=2, dklen=32)
```

### Decryption steps in `decrypt_db.py`

1. **Detect** `db_storage` — globs `~/Library/Containers/com.tencent.xinWeChat/
   Data/Documents/xwechat_files/*/db_storage` and picks the account with the most
   recently modified `sns/` directory.
2. **Find the key** for the target database:
   1. Exact match of the database's relative path (e.g. `sns/sns.db`) in
      `all_keys.json` (path separators normalized so Windows/Linux keys also match).
   2. Fallback: brute-force HMAC — read the 16-byte salt from the file and verify
      each known key against page 1's stored HMAC (cheap: one PBKDF2 + HMAC per key).
3. **Decrypt** page by page:
   - Page 1: take `page[16:4016]`, AES-CBC-decrypt with the IV from `page[4016:4032]`,
     then reassemble as `b"SQLite format 3\0"` (16 bytes) + decrypted + 80 zero bytes.
   - Other pages: decrypt `page[0:4016]`, append 80 zero bytes.
   - Writing zeros over the reserve area is safe: the B-tree inside the decrypted
     pages was built with `usable_size = 4016`, so SQLite never reads those bytes.
4. **Verify & save** — write to a new file (`decrypted/sns/sns.db`), open it with
   plaintext `sqlite3`, checkpoint + remove any `-wal`/`-shm` residue.

## Where the keys come from

`all_keys.json` maps relative db paths to 64-char hex keys:

```json
{
  "sns/sns.db":   { "enc_key": "10c3853c1680e022e6575685356b49c810fa16ec95c3c0f80cb7b7e7ef738c62" },
  "message/message_0.db": { "enc_key": "..." },
  ...
}
```

The keys are extracted from WeChat's process memory by the sibling project
[wechat-decrypt](../wechat-decrypt) (`find_all_keys_macos.c`), which scans process
memory for the `x'<key_hex><salt_hex>'` SQLCipher PRAGMA string that WeChat keeps
in memory while running, then pairs each key with a database by matching the salt
read from each `.db` file. Requirements: WeChat running and ad-hoc signed (or SIP
disabled), run under `sudo`:

```bash
cd wechat-decrypt && sudo ./find_all_keys_macos
```

`decrypt_db.py` locates this file automatically (env `WECHAT_DECRYPT_KEYS`, then
`../wechat-decrypt/all_keys.json`, then `./all_keys.json`) or takes `--keys-file`.

## Notes & caveats

- **Close WeChat before decrypting** if you want the newest data: WeChat keeps
  recent writes in `sns.db-wal`, and this tool decrypts the main `sns.db` file
  only.
- Decrypted databases are still in WAL journal mode; opening them read-only with
  SQLite without an existing `-shm` file fails with "unable to open database
  file", so verification opens them read-write (this matches the reference
  implementation in wechat-decrypt).
- Verified result on this machine: 18/18 databases decrypt successfully;
  `SnsTimeLine` contains 2548 rows.

## Next steps

- [x] Export `SnsTimeLine` rows to plain JSON
- [x] Download SNS media from CDN (kept encrypted, with manifest & checksum tracking)
- [x] Decrypt CDN media (ISAAC-64 via WeChat's official WASM module)
- [x] WeChat Moments web reader (React + Tailwind, Flask + SQLite, pagination & search)
- [x] Cryptowl vault tooling (`vaultlib/`) + moments migration (`migrate_moments.py`)

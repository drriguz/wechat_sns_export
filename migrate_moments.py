"""
Migrate a WeChat SNS export into a cryptowl vault (Confidential tier).

Workflow: copy the vault dir off the Android device -> run this -> copy back.

1. Opens the vault with the master password (full verification: meta mac,
   config.sig, VaultKey unwrap, SQLCipher raw key) and derives FEK.
2. Ensures the moments feature schema (docs/moments.sql, idempotent).
3. Encrypts every decrypted media file with FEK into CWO1 files:
       attachments/<media_id>.cwo          (whole-file GCM for images/audio)
       attachments/<media_id>.cwo          (chunked 64 KiB GCM for videos)
       thumbnails/<media_id>_t.cwo         (whole-file GCM, same FEK)
   AAD = media row id on every GCM operation (design.md anti-swap rule).
4. Inserts t_moment / t_moment_card / t_moment_media / t_moment_comment /
   t_moment_like rows (deterministic UUIDs, idempotent by source_id).

File formats (cryptowl/docs/moments.md §4):
    whole-file: 22 B header = b'CWO1' u16(1) u32(0) nonce(12) + ct + tag(16)
    chunked:    22 B header = b'CWO1' u16(1) u32(65536) u64(count) iv_prefix(4)
                + records[ct(<=64KiB) + tag(16)]
    chunk nonce = u64(chunk_index).to_bytes(8,'big') + iv_prefix

Usage:
    python migrate_moments.py --vault ../cryptowl/docs/../vault-dir ...
    python migrate_moments.py --vault <vault-dir> --password <master-password>
                              --json decrypted/sns_export.json
                              --media decrypted/media_decrypted
                              [--schema ../cryptowl/docs/moments.sql]
"""
import argparse
import datetime
import json
import os
import sys
import uuid

from Crypto.Cipher import AES

from vaultlib.vault import Vault

MAGIC = b"CWO1"
VERSION = 1
CHUNK_SIZE = 65536
HEADER_LEN = 22
TAG_LEN = 16

MIME = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".heic": "image/heic", ".heif": "image/heif",
    ".mp4": "video/mp4", ".mov": "video/quicktime",
    ".m4a": "audio/mp4", ".mp3": "audio/mpeg",
}
VIDEO_EXTS = {".mp4", ".mov"}
AUDIO_EXTS = {".m4a", ".mp3"}

NS = uuid.UUID("a9b7c4d2-0000-4f00-9000-000000000001")


def uid(scope: str, key: str) -> str:
    return str(uuid.uuid5(NS, f"cryptowl:{scope}:{key}"))


# ---------------------------------------------------------------------------
# CWO1 file encryption (FEK, AAD = media row id)
# ---------------------------------------------------------------------------

def enc_whole_file(fek: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    header = MAGIC + VERSION.to_bytes(2, "big") + (0).to_bytes(4, "big") + nonce
    cipher = AES.new(fek, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return header + ct + tag


def enc_chunked_file(fek: bytes, plaintext: bytes, aad: bytes) -> bytes:
    iv_prefix = os.urandom(4)
    n = (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE
    header = (MAGIC + VERSION.to_bytes(2, "big")
              + CHUNK_SIZE.to_bytes(4, "big") + n.to_bytes(8, "big")
              + iv_prefix)
    out = bytearray(header)
    for i in range(n):
        chunk = plaintext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        nonce = i.to_bytes(8, "big") + iv_prefix
        cipher = AES.new(fek, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(chunk)
        out += ct + tag
    return bytes(out)


# ---------------------------------------------------------------------------
# Schema (single source of truth: cryptowl/docs/moments.sql)
# ---------------------------------------------------------------------------

def ensure_schema(vault: Vault, schema_path: str) -> None:
    if not os.path.isfile(schema_path):
        raise SystemExit(f"moments schema not found: {schema_path}")
    with open(schema_path, encoding="utf-8") as f:
        sql = f.read()
    # Idempotent variant of the doc schema; sqlite3_exec runs the whole script
    # (comments and multi-statement triggers included) in one call
    sql = (sql.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
             .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
             .replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS "))
    vault.conn.exec_(sql)


# ---------------------------------------------------------------------------
# Type mapping from the WeChat export
# ---------------------------------------------------------------------------

def map_type(content_type, has_finder):
    if content_type == 1:
        return "media"
    if content_type == 2:
        return "text"
    if content_type in (3, 5):
        return "link"
    if content_type == 7:
        return "location"
    if content_type == 15:
        return "media"
    if content_type == 28:
        return "link" if has_finder else "media"
    if content_type == 30:
        return "music"
    if content_type == 34:
        return "note"
    if content_type == 42:
        return "mini_program"
    if content_type == 54:
        return "live"
    return "media"


def card_info(post):
    """Return (card_type, fields) for link/finder posts, else None."""
    f = post.get("finder")
    if f and f.get("nickname"):
        return "finder", {
            "title": None, "description": f.get("desc") or None,
            "source_name": "视频号", "url": f.get("video_url") or None,
            "author_name": f.get("nickname") or None,
            "author_avatar_filename": None, "thumb_file": None,
        }
    lk = post.get("link")
    if lk and (lk.get("title") or lk.get("description") or lk.get("source")):
        return ("video_link" if post.get("content_type") == 5 else "link"), {
            "title": lk.get("title") or None,
            "description": lk.get("description") or None,
            "source_name": lk.get("source") or None,
            "url": post.get("link_url") or None,
            "author_name": None, "author_avatar_filename": None, "thumb_file": None,
        }
    return None


def resolve_media_files(media_dir: str):
    """{stem: (full_filename, thumb_filename)} from the decrypted dir."""
    resolved, thumbs = {}, {}
    for name in os.listdir(media_dir):
        stem, ext = os.path.splitext(name)
        if ext.lower() not in MIME:
            continue
        if stem.endswith("_t"):
            thumbs.setdefault(stem[:-2], name)
        else:
            resolved.setdefault(stem, name)
    return {s: (f, thumbs.get(s, "")) for s, f in resolved.items()}


def sql_str(v):
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def sql_int(v):
    return "NULL" if v is None else str(int(v))


def sql_blob(data):
    return "X'" + data.hex() + "'" if data is not None else "NULL"


def main():
    parser = argparse.ArgumentParser(
        description="Migrate a WeChat SNS export into a cryptowl vault")
    parser.add_argument("--vault", required=True, help="vault directory")
    parser.add_argument("--password", help="master password")
    parser.add_argument("--password-file", type=argparse.FileType("rb"),
                        help="read the master password from a file")
    parser.add_argument("--json", default=os.path.join("decrypted", "sns_export.json"))
    parser.add_argument("--media", default=os.path.join("decrypted", "media_decrypted"))
    parser.add_argument("--schema",
                        default=os.path.join("..", "cryptowl", "docs", "moments.sql"))
    args = parser.parse_args()

    if args.password:
        password = args.password.encode("utf-8")
    elif args.password_file:
        password = args.password_file.read().strip()
    else:
        raise SystemExit("missing --password or --password-file")

    if not os.path.isfile(args.json):
        raise SystemExit(f"export json not found: {args.json}")
    with open(args.json, encoding="utf-8") as f:
        export = json.load(f)
    posts = export.get("posts", [])

    with Vault.open(args.vault, password) as vault:
        vault.ensure_dirs()
        ensure_schema(vault, args.schema)
        fek = vault.file_encryption_key
        files = resolve_media_files(args.media)

        n_moment = n_card = n_media = n_comment = n_like = n_skipped_media = 0
        existing = {r[0] for r in vault.conn.query("SELECT source_id FROM t_moment WHERE source_id IS NOT NULL")}

        for post in posts:
            sid = str(post.get("id") or post["tid"])
            if sid in existing:
                continue  # idempotent re-import
            mid = uid("moment", sid)
            ctype = post.get("content_type", 0)
            mtype = map_type(ctype, bool(post.get("finder")))

            loc = post.get("location")
            loc_json = json.dumps(loc, ensure_ascii=False) if loc else None
            ts_ms = int(post.get("create_time") or 0) * 1000
            created = datetime.datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
            visibility = "private" if post.get("is_private") else "friends"

            vault.conn.exec_(
                "INSERT OR IGNORE INTO t_moment (id, classification, type,"
                " author_name, author_username, content, location, visibility,"
                " source_id, source_created_at, created_at, updated_at)"
                " VALUES (" + sql_str(mid) + ", 'C', " + sql_str(mtype) + ", "
                + sql_str(post.get("nickname") or post.get("username")) + ", "
                + sql_str(post.get("username")) + ", "
                + sql_str(post.get("content_desc") or None) + ", "
                + sql_str(loc_json) + ", " + sql_str(visibility) + ", "
                + sql_str(sid) + ", " + sql_int(ts_ms) + ", "
                + sql_str(created) + ", " + sql_str(created) + ");")
            n_moment += 1
            existing.add(sid)

            # -- card (link / video_link / finder) ---------------------------
            card = card_info(post)
            if card:
                card_type, fields = card
                cid = uid("card", sid)
                thumb_file = None
                if post.get("media"):
                    stem = str(post["media"][0].get("id") or "").strip() or f"{post['tid']}_0"
                    f0 = files.get(stem)
                    if f0 and f0[0]:
                        thumb_file = f0[0]
                cover_src = None
                if not thumb_file:
                    for suffix in ("_card.jpg", "_finder.jpg"):
                        p = os.path.join(args.media, f"{sid}{suffix}")
                        if os.path.isfile(p):
                            cover_src = p
                            break
                thumb_filename = None
                if thumb_file or cover_src:
                    src = cover_src or os.path.join(args.media, thumb_file)
                    with open(src, "rb") as fh:
                        cover = enc_whole_file(fek, fh.read(), cid.encode("ascii"))
                    thumb_filename = f"{cid}.cwo"
                    _write_if_missing(os.path.join(vault.attachments_dir, thumb_filename), cover)
                vault.conn.exec_(
                    "INSERT OR IGNORE INTO t_moment_card (id, moment_id, card_type,"
                    " title, description, source_name, url, thumb_filename,"
                    " author_name, author_avatar_filename, created_at, updated_at)"
                    " VALUES ("
                    + sql_str(cid) + ", " + sql_str(mid) + ", " + sql_str(card_type)
                    + ", " + sql_str(fields["title"]) + ", "
                    + sql_str(fields["description"]) + ", "
                    + sql_str(fields["source_name"]) + ", " + sql_str(fields["url"])
                    + ", " + sql_str(thumb_filename) + ", "
                    + sql_str(fields["author_name"]) + ", NULL, "
                    + sql_int(ts_ms) + ", " + sql_int(ts_ms) + ");")
                n_card += 1

            # -- media ---------------------------------------------------------
            for idx, md in enumerate(post.get("media", [])):
                stem = str(md.get("id") or "").strip() or f"{post['tid']}_{idx}"
                f0 = files.get(stem)
                if not f0 or not f0[0]:
                    n_skipped_media += 1
                    continue
                full_name, thumb_name = f0
                ext = os.path.splitext(full_name)[1].lower()
                media_id = uid("media", f"{sid}:{idx}")
                aad = media_id.encode("ascii")

                is_video = ext in VIDEO_EXTS
                fname = f"{media_id}.cwo"
                out_path = os.path.join(vault.attachments_dir, fname)
                if not os.path.isfile(out_path):
                    with open(os.path.join(args.media, full_name), "rb") as fh:
                        plaintext = fh.read()
                    enc = (enc_chunked_file(fek, plaintext, aad) if is_video
                           else enc_whole_file(fek, plaintext, aad))
                    _write_if_missing(out_path, enc)

                thumb_filename = None
                if thumb_name:
                    tp = os.path.join(args.media, thumb_name)
                    if os.path.isfile(tp):
                        thumb_filename = f"{media_id}_t.cwo"
                        tp_out = os.path.join(vault.thumbnails_dir, thumb_filename)
                        if not os.path.isfile(tp_out):
                            with open(tp, "rb") as fh:
                                _write_if_missing(tp_out,
                                                  enc_whole_file(fek, fh.read(), aad))

                width = height = duration_ms = None
                try:
                    if md.get("width"):
                        width = int(md["width"])
                    if md.get("height"):
                        height = int(md["height"])
                    if md.get("video_duration"):
                        duration_ms = int(float(md["video_duration"]) * 1000)
                except (TypeError, ValueError):
                    pass

                if is_video:
                    mtype_media = "video"
                elif ext in AUDIO_EXTS:
                    mtype_media = "audio"
                else:
                    mtype_media = "image"

                vault.conn.exec_(
                    "INSERT OR IGNORE INTO t_moment_media (id, moment_id,"
                    " media_type, classification, filename, original_name,"
                    " mime_type, size_bytes, width, height, duration_ms,"
                    " thumbnail_filename, sort_order, created_at, updated_at)"
                    " VALUES ("
                    + sql_str(media_id) + ", " + sql_str(mid) + ", "
                    + sql_str(mtype_media) + ", 'C', " + sql_str(fname) + ", "
                    + sql_str(full_name) + ", "
                    + sql_str(MIME.get(ext, "application/octet-stream")) + ", "
                    + sql_int(os.path.getsize(os.path.join(args.media, full_name)))
                    + ", " + sql_int(width) + ", " + sql_int(height) + ", "
                    + sql_int(duration_ms) + ", " + sql_str(thumb_filename) + ", "
                    + str(idx) + ", " + sql_int(ts_ms) + ", " + sql_int(ts_ms) + ");")
                n_media += 1

            # -- comments (top-level first, then replies) ----------------------
            by_wx_id = {}
            for c in post.get("comments", []):
                wid = c.get("comment_id")
                by_wx_id[wid] = uid("comment", f"{sid}:{wid}")
            for c in post.get("comments", []):
                ref = c.get("ref_comment_id")
                parent = by_wx_id.get(ref) if (ref in by_wx_id and ref != c.get("comment_id")) else None
                vault.conn.exec_(
                    "INSERT OR IGNORE INTO t_moment_comment (id, moment_id,"
                    " parent_id, author_name, author_username, content,"
                    " classification, created_at) VALUES ("
                    + sql_str(by_wx_id[c.get("comment_id")]) + ", "
                    + sql_str(mid) + ", " + sql_str(parent) + ", "
                    + sql_str(c.get("nickname") or c.get("username")) + ", "
                    + sql_str(c.get("username")) + ", "
                    + sql_str(c.get("content") or None) + ", 'C', "
                    + sql_str(datetime.datetime.fromtimestamp(int(c.get("create_time") or 0)).strftime("%Y-%m-%d %H:%M:%S")) + ");")
                n_comment += 1

            # -- likes -----------------------------------------------------------
            for lk in post.get("likes", []):
                vault.conn.exec_(
                    "INSERT OR IGNORE INTO t_moment_like (moment_id,"
                    " author_username, author_name, created_at) VALUES ("
                    + sql_str(mid) + ", " + sql_str(lk.get("username")) + ", "
                    + sql_str(lk.get("nickname") or lk.get("username")) + ", "
                    + sql_str(datetime.datetime.fromtimestamp(int(lk.get("create_time") or 0)).strftime("%Y-%m-%d %H:%M:%S")) + ");")
                n_like += 1

        print(f"[+] vault       : {vault.path} (vault_id={vault.vault_id})")
        print(f"[+] moments     : {n_moment}  cards: {n_card}  media: {n_media}"
              f"  comments: {n_comment}  likes: {n_like}")
        print(f"[+] skipped media (no decrypted file): {n_skipped_media}")
        print(f"[+] attachments : {_dir_size(vault.attachments_dir)} files"
              f" ({_dir_mb(vault.attachments_dir)} MB)")
        print(f"[+] thumbnails  : {_dir_size(vault.thumbnails_dir)} files"
              f" ({_dir_mb(vault.thumbnails_dir)} MB)")
        print("[+] done — copy the vault back to Android")
    return 0


def _write_if_missing(path: str, data: bytes) -> None:
    if not os.path.isfile(path):
        with open(path, "wb") as f:
            f.write(data)


def _dir_size(path: str) -> int:
    return len(os.listdir(path)) if os.path.isdir(path) else 0


def _dir_mb(path: str) -> int:
    if not os.path.isdir(path):
        return 0
    return sum(os.path.getsize(os.path.join(path, f))
               for f in os.listdir(path)) // 1048576


if __name__ == "__main__":
    sys.exit(main())

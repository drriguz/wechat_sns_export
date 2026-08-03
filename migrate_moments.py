"""
One-time migration: WeChat SNS export -> cryptowl moments (encrypted vault).

1. Encrypt every decrypted media file (whole-file AES-256-GCM for images,
   chunked 64 KiB AES-256-GCM for videos/audio) into <output>/media_encrypted/
2. Record every DEK in <output>/migration_keys.json — the DEKs are RAW (the
   master password / wrapping keys are not known yet); the final migration
   wraps them with VaultKey/KEK/TopSecretKEK and fills t_data_encrypt_key.
3. Generate <output>/moments_import.sql — plaintext INSERTs (C classification)
   for t_moment / t_moment_card / t_moment_media / t_moment_comment /
   t_moment_like. SQLCipher encrypts the DB at rest; thumbnails are embedded
   as BLOBs.

File formats (see cryptowl/docs/moments.sql):

    whole-file (images):  22 B header = b'CWO1' u16(1) u32(0) nonce(12)
                          + ciphertext + tag(16)
    chunked (video/audio):22 B header = b'CWO1' u16(1) u32(65536) u64(count)
                          iv_prefix(4) + records[ciphertext(<=64KiB)+tag(16)]
    chunk nonce = u64(chunk_index).to_bytes(8,'big') + iv_prefix
    AAD = media row id (uuid, ascii) on every GCM operation

Usage:
    python migrate_moments.py [--json decrypted/sns_export.json]
                              [--media decrypted/media_decrypted]
                              [--output ../cryptowl/docs/migration]
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
import uuid

from Crypto.Cipher import AES

MAGIC = b"CWO1"
VERSION = 1
CHUNK_SIZE = 65536
HEADER_LEN = 22  # both layouts
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


def uid(scope, key):
    return str(uuid.uuid5(NS, f"cryptowl:{scope}:{key}"))


def enc_whole_file(dek, plaintext, aad):
    nonce = os.urandom(12)
    header = MAGIC + VERSION.to_bytes(2, "big") + (0).to_bytes(4, "big") + nonce
    cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return header + ct + tag, nonce


def enc_chunked_file(dek, plaintext, aad):
    iv_prefix = os.urandom(4)
    n = (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE
    header = (MAGIC + VERSION.to_bytes(2, "big")
              + CHUNK_SIZE.to_bytes(4, "big") + n.to_bytes(8, "big")
              + iv_prefix)
    out = bytearray(header)
    for i in range(n):
        chunk = plaintext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        nonce = i.to_bytes(8, "big") + iv_prefix
        cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(chunk)
        out += ct + tag
    return bytes(out), iv_prefix


def sql_str(v):
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def sql_blob(data):
    return "X'" + data.hex() + "'" if data is not None else "NULL"


def sql_int(v):
    return "NULL" if v is None else str(int(v))


def dt(ts):
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")


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
    """Return (card_type, card_fields) for link/finder posts, else None."""
    f = post.get("finder")
    if f and f.get("nickname"):
        return "finder", {
            "title": None,
            "description": f.get("desc") or None,
            "source_name": "视频号",
            "url": f.get("video_url") or None,
            "author_name": f.get("nickname") or None,
            "author_avatar_filename": None,
            "thumb_file": None,
        }
    lk = post.get("link")
    if lk and (lk.get("title") or lk.get("description") or lk.get("source")):
        return ("video_link" if post.get("content_type") == 5 else "link"), {
            "title": lk.get("title") or None,
            "description": lk.get("description") or None,
            "source_name": lk.get("source") or None,
            "url": post.get("link_url") or None,
            "author_name": None,
            "author_avatar_filename": None,
            "thumb_file": None,
        }
    return None


def resolve_media_files(media_dir):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default=os.path.join("decrypted", "sns_export.json"))
    parser.add_argument("--media", default=os.path.join("decrypted", "media_decrypted"))
    parser.add_argument("--output", default="migration")
    args = parser.parse_args()

    with open(args.json, encoding="utf-8") as f:
        export = json.load(f)
    posts = export.get("posts", [])
    files = resolve_media_files(args.media)

    out_media = os.path.join(args.output, "media_encrypted")
    os.makedirs(out_media, exist_ok=True)

    manifest = {
        "generated_at": datetime.datetime.now().isoformat(),
        "algorithm": "AES-256-GCM",
        "header": {"magic": MAGIC.decode(), "version": VERSION,
                   "header_bytes": HEADER_LEN, "chunk_size": CHUNK_SIZE},
        "aad": "media row id (uuid, ascii)",
        "note": "DEKs are RAW. Final migration: wrap with VaultKey (C) and "
                "insert t_data_encrypt_key rows using these ids.",
        "keys": {},
    }
    card_files = {}
    sql = ["-- cryptowl moments import (C classification)",
           "-- generated by migrate_moments.py",
           "-- NOTE: t_data_encrypt_key rows are intentionally NOT created here;",
           "-- the key-wrapping migration inserts them from migration_keys.json.",
           "-- Enable PRAGMA foreign_keys = ON only after that step.",
           "BEGIN TRANSACTION;"]

    n_media = n_card = n_comment = n_like = n_moment = 0

    for post in posts:
        sid = post.get("id") or str(post["tid"])
        mid = uid("moment", sid)
        ctype = post.get("content_type", 0)
        has_finder = bool(post.get("finder"))
        mtype = map_type(ctype, has_finder)

        loc = post.get("location")
        loc_json = json.dumps(loc, ensure_ascii=False) if loc else None
        created = dt(post.get("create_time"))
        sql.append(
            "INSERT INTO t_moment (id, classification, type, author_name,"
            " author_username, content, location, is_private, source_id,"
            " source_created_at, created_at, updated_at) VALUES ("
            + sql_str(mid) + ", 'C', " + sql_str(mtype) + ", "
            + sql_str(post.get("nickname") or post.get("username")) + ", "
            + sql_str(post.get("username")) + ", "
            + sql_str(post.get("content_desc") or None) + ", "
            + sql_str(loc_json) + ", " + str(1 if post.get("is_private") else 0)
            + ", " + sql_str(sid) + ", " + sql_int(post.get("create_time") or 0)
            + ", " + sql_str(created) + ", " + sql_str(created) + ");")
        n_moment += 1

        # -- card (link / video_link / finder) -------------------------------
        card = card_info(post)
        if card:
            card_type, fields = card
            cid = uid("card", sid)
            # card cover: first local media file, else fetched _card/_finder jpg
            thumb_file = None
            if post.get("media"):
                stem = str(post["media"][0].get("id") or "").strip() or f"{post['tid']}_0"
                f0 = files.get(stem)
                if f0 and f0[0]:
                    thumb_file = f0[0]
            if not thumb_file:
                for suffix in ("_card.jpg", "_finder.jpg"):
                    p = os.path.join(args.media, f"{sid}{suffix}")
                    if os.path.isfile(p):
                        thumb_file = f"{sid}{suffix}"
                        card_files[cid] = p
                        break
            sql.append(
                "INSERT INTO t_moment_card (id, moment_id, card_type, title,"
                " description, source_name, url, thumb_filename, author_name,"
                " author_avatar_filename) VALUES ("
                + sql_str(cid) + ", " + sql_str(mid) + ", " + sql_str(card_type)
                + ", " + sql_str(fields["title"]) + ", "
                + sql_str(fields["description"]) + ", "
                + sql_str(fields["source_name"]) + ", " + sql_str(fields["url"])
                + ", NULL, " + sql_str(fields["author_name"]) + ", NULL);")
            n_card += 1

        # -- media ------------------------------------------------------------
        for idx, md in enumerate(post.get("media", [])):
            stem = str(md.get("id") or "").strip() or f"{post['tid']}_{idx}"
            f0 = files.get(stem)
            if not f0 or not f0[0]:
                continue
            full_name, thumb_name = f0
            src_path = os.path.join(args.media, full_name)
            ext = os.path.splitext(full_name)[1].lower()
            media_id = uid("media", f"{sid}:{idx}")
            dek_id = uid("dek", media_id)
            dek = os.urandom(32)
            aad = media_id.encode("ascii")

            with open(src_path, "rb") as fh:
                plaintext = fh.read()
            is_video = ext in VIDEO_EXTS
            if is_video:
                enc, iv_prefix = enc_chunked_file(dek, plaintext, aad)
                chunk_size, chunk_count = CHUNK_SIZE, (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE
                iv_hex = iv_prefix.hex()
                nonce_hex = None
            else:
                enc, nonce = enc_whole_file(dek, plaintext, aad)
                chunk_size, chunk_count, iv_hex = None, None, None
                nonce_hex = nonce.hex()

            fname = f"{media_id}.cwo"
            with open(os.path.join(out_media, fname), "wb") as fh:
                fh.write(enc)

            thumb = None
            if thumb_name:
                tp = os.path.join(args.media, thumb_name)
                if os.path.isfile(tp):
                    with open(tp, "rb") as fh:
                        thumb = fh.read()

            manifest["keys"][dek_id] = {
                "dek_hex": dek.hex(),
                "classification": "C",
                "wrapping": "vault",
                "media_id": media_id,
                "filename": fname,
                "chunk_size": chunk_size,
                "chunk_count": chunk_count,
                "iv_prefix_hex": iv_hex,
                "nonce_hex": nonce_hex,
            }

            width = md.get("width") or None
            height = md.get("height") or None
            duration = md.get("video_duration") or None
            try:
                width = int(width) if width else None
                height = int(height) if height else None
                duration_ms = int(float(duration) * 1000) if duration else None
            except (TypeError, ValueError):
                width, height, duration_ms = None, None, None

            sql.append(
                "INSERT INTO t_moment_media (id, moment_id, media_type,"
                " classification, filename, mime_type, width, height,"
                " duration_ms, chunk_size, chunk_count, iv_prefix, thumbnail,"
                " encrypted_dek_id, sort_order) VALUES ("
                + sql_str(media_id) + ", " + sql_str(mid) + ", "
                + sql_str("video" if is_video else "image") + ", 'C', "
                + sql_str(fname) + ", " + sql_str(MIME.get(ext, "application/octet-stream"))
                + ", " + sql_int(width) + ", " + sql_int(height) + ", "
                + sql_int(duration_ms) + ", " + sql_int(chunk_size) + ", "
                + sql_int(chunk_count) + ", " + sql_blob(bytes.fromhex(iv_hex) if iv_hex else None)
                + ", " + sql_blob(thumb) + ", " + sql_str(dek_id) + ", "
                + str(idx) + ");")
            n_media += 1

        # -- comments (two passes: top-level first, then replies, so the
        #    parent_id FK always resolves) -----------------------------------
        by_wx_id = {}
        for c in post.get("comments", []):
            wid = c.get("comment_id")
            by_wx_id[wid] = uid("comment", f"{sid}:{wid}")
        for c in post.get("comments", []):
            ref = c.get("ref_comment_id")
            if ref not in by_wx_id or ref == c.get("comment_id"):
                sql.append(
                    "INSERT INTO t_moment_comment (id, moment_id, parent_id,"
                    " author_name, author_username, content, classification,"
                    " created_at) VALUES (" + sql_str(by_wx_id[c.get("comment_id")])
                    + ", " + sql_str(mid) + ", NULL, "
                    + sql_str(c.get("nickname") or c.get("username")) + ", "
                    + sql_str(c.get("username")) + ", "
                    + sql_str(c.get("content") or None) + ", 'C', "
                    + sql_str(dt(c.get("create_time"))) + ");")
                n_comment += 1
        for c in post.get("comments", []):
            ref = c.get("ref_comment_id")
            if ref in by_wx_id and ref != c.get("comment_id"):
                sql.append(
                    "INSERT INTO t_moment_comment (id, moment_id, parent_id,"
                    " author_name, author_username, content, classification,"
                    " created_at) VALUES (" + sql_str(by_wx_id[c.get("comment_id")])
                    + ", " + sql_str(mid) + ", " + sql_str(by_wx_id[ref]) + ", "
                    + sql_str(c.get("nickname") or c.get("username")) + ", "
                    + sql_str(c.get("username")) + ", "
                    + sql_str(c.get("content") or None) + ", 'C', "
                    + sql_str(dt(c.get("create_time"))) + ");")
                n_comment += 1

        # -- likes ------------------------------------------------------------
        for lk in post.get("likes", []):
            sql.append(
                "INSERT INTO t_moment_like (moment_id, author_username,"
                " author_name, created_at) VALUES (" + sql_str(mid) + ", "
                + sql_str(lk.get("username")) + ", "
                + sql_str(lk.get("nickname") or lk.get("username")) + ", "
                + sql_str(dt(lk.get("create_time"))) + ");")
            n_like += 1

    # -- encrypt extra card covers (fetched _card.jpg / _finder.jpg) ----------
    for cid, src_path in card_files.items():
        with open(src_path, "rb") as fh:
            plaintext = fh.read()
        dek_id = uid("dek", f"card:{cid}")
        dek = os.urandom(32)
        aad = cid.encode("ascii")
        enc, nonce = enc_whole_file(dek, plaintext, aad)
        fname = f"{cid}.cwo"
        with open(os.path.join(out_media, fname), "wb") as fh:
            fh.write(enc)
        manifest["keys"][dek_id] = {
            "dek_hex": dek.hex(), "classification": "C", "wrapping": "vault",
            "media_id": cid, "filename": fname, "chunk_size": None,
            "chunk_count": None, "iv_prefix_hex": None, "nonce_hex": nonce.hex(),
        }
        sql.append(
            "UPDATE t_moment_card SET thumb_filename = " + sql_str(fname)
            + " WHERE id = " + sql_str(cid) + ";")

    sql.append("COMMIT;")

    with open(os.path.join(args.output, "migration_keys.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    with open(os.path.join(args.output, "moments_import.sql"), "w", encoding="utf-8") as f:
        f.write("\n".join(sql) + "\n")

    print(f"[+] moments: {n_moment}  cards: {n_card}  media: {n_media}"
          f"  comments: {n_comment}  likes: {n_like}")
    print(f"[+] encrypted files: {len(os.listdir(out_media))}"
          f" ({sum(os.path.getsize(os.path.join(out_media, f)) for f in os.listdir(out_media))/1048576:.0f} MB)")
    print(f"[+] keys manifest: {os.path.join(args.output, 'migration_keys.json')}"
          f" ({len(manifest['keys'])} DEKs)")
    print(f"[+] sql: {os.path.join(args.output, 'moments_import.sql')}"
          f" ({os.path.getsize(os.path.join(args.output, 'moments_import.sql'))/1048576:.0f} MB)")
    print("[!] DEKs are RAW — final migration wraps them with VaultKey and")
    print("    inserts t_data_encrypt_key rows (see migration_keys.json).")


if __name__ == "__main__":
    sys.exit(main())

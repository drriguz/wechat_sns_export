"""
Ingest decrypted/sns_export.json into SQLite for the Flask API.

Tables:
    posts  - one row per SNS post (likes/comments stored as JSON)
    media  - one row per media element, resolved to a decrypted file

Usage:
    python backend/ingest.py [--json decrypted/sns_export.json] [--db decrypted/sns.sqlite]
"""
import argparse
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_JSON = os.path.join("decrypted", "sns_export.json")
DEFAULT_DB = os.path.join("decrypted", "sns.sqlite")
MEDIA_DIR = os.path.join("decrypted", "media_decrypted")

SCHEMA = """
CREATE TABLE IF NOT EXISTS posts (
    tid INTEGER PRIMARY KEY,
    feed_id TEXT,
    username TEXT,
    nickname TEXT,
    create_time INTEGER,
    create_time_str TEXT,
    content_desc TEXT,
    content_type INTEGER,
    content_type_name TEXT,
    is_private INTEGER,
    location TEXT,
    likes TEXT,
    comments TEXT,
    link_url TEXT,
    link_title TEXT,
    link_description TEXT,
    link_source TEXT,
    link_thumb_url TEXT,
    finder TEXT
);
CREATE TABLE IF NOT EXISTS media (
    media_id TEXT PRIMARY KEY,
    post_tid INTEGER,
    media_index INTEGER,
    mtype TEXT,
    width INTEGER,
    height INTEGER,
    file TEXT,
    thumb_file TEXT
);
CREATE INDEX IF NOT EXISTS idx_media_post ON media(post_tid);
"""


def media_stem(md, post_tid, idx):
    mid = str(md.get("id") or "").strip()
    return mid or f"{post_tid}_{idx}"


def extract_link_url(post):
    """The link target lives in the post XML as <contentUrl>...</contentUrl>.

    Some posts carry a generic WeChat support placeholder page instead of a
    real link — those must not be treated as links.
    """
    m = re.search(r"<contentUrl>(.*?)</contentUrl>", post.get("raw_xml", "") or "")
    url = m.group(1).strip() if m and m.group(1).strip() else ""
    if "support.weixin.qq.com" in url:
        return ""
    return url


def resolve_media_files(media_dir, ext_priority=(".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".bmp", ".heic")):
    """Scan the decrypted media dir.

    Returns {stem: (full_filename, thumb_filename)}. The thumb may have a
    different extension than the full file (e.g. video + jpg cover), so the
    real `_t.*` files are resolved by scanning, not derived.
    """
    resolved = {}
    thumbs = {}
    try:
        names = os.listdir(media_dir)
    except OSError:
        return resolved
    for name in names:
        stem, ext = os.path.splitext(name)
        if ext.lower() not in ext_priority:
            continue
        if stem.endswith("_t"):
            thumbs.setdefault(stem[:-2], name)
        else:
            resolved.setdefault(stem, name)
    return {stem: (fname, thumbs.get(stem, "")) for stem, fname in resolved.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default=DEFAULT_JSON)
    parser.add_argument("--db", default=DEFAULT_DB)
    args = parser.parse_args()

    with open(args.json, encoding="utf-8") as f:
        export = json.load(f)
    posts = export.get("posts", [])

    conn = sqlite3.connect(args.db)
    conn.executescript("DROP TABLE IF EXISTS posts")
    conn.executescript("DROP TABLE IF EXISTS media")
    conn.executescript(SCHEMA)
    files = resolve_media_files(MEDIA_DIR)
    print(f"[+] resolved {len(files)} decrypted media files")

    conn.execute("DELETE FROM posts")
    conn.execute("DELETE FROM media")
    n_media = 0
    for p in posts:
        conn.execute(
            "INSERT INTO posts (tid, feed_id, username, nickname, create_time,"
            " create_time_str, content_desc, content_type, content_type_name,"
            " is_private, location, likes, comments, link_url, link_title,"
            " link_description, link_source, link_thumb_url, finder)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                p["tid"], p.get("id", ""), p.get("username", ""),
                p.get("nickname", ""), p.get("create_time", 0),
                p.get("create_time_str", ""), p.get("content_desc", ""),
                p.get("content_type", 0), p.get("content_type_name", ""),
                1 if p.get("is_private") else 0,
                json.dumps(p.get("location"), ensure_ascii=False),
                json.dumps(p.get("likes", []), ensure_ascii=False),
                json.dumps(p.get("comments", []), ensure_ascii=False),
                extract_link_url(p),
                (p.get("link") or {}).get("title", ""),
                (p.get("link") or {}).get("description", ""),
                (p.get("link") or {}).get("source", ""),
                (p.get("link") or {}).get("thumb_url", ""),
                json.dumps(p.get("finder"), ensure_ascii=False) if p.get("finder") else None,
            ),
        )
        for idx, md in enumerate(p.get("media", [])):
            stem = media_stem(md, p["tid"], idx)
            width = md.get("width") or 0
            height = md.get("height") or 0
            try:
                width = int(width)
            except (TypeError, ValueError):
                width = 0
            try:
                height = int(height)
            except (TypeError, ValueError):
                height = 0
            conn.execute(
                "INSERT INTO media (media_id, post_tid, media_index, mtype,"
                " width, height, file, thumb_file) VALUES (?,?,?,?,?,?,?,?)",
                (stem, p["tid"], idx, str(md.get("type", "")), width, height,
                 files.get(stem, ("", ""))[0],
                 files.get(stem, ("", ""))[1]),
            )
            n_media += 1
    conn.commit()
    conn.close()
    print(f"[+] ingested {len(posts)} posts, {n_media} media -> {args.db}")


if __name__ == "__main__":
    main()

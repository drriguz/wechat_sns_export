"""
Flask API for the WeChat SNS reader.

Endpoints:
    GET /api/posts?page=1&page_size=10&search=keyword   paginated post list
    GET /api/posts/<tid>                                single post
    GET /api/stats                                      counts
    /media/<filename>                                   decrypted media files

Run:
    .venv/bin/python backend/ingest.py
    .venv/bin/python backend/app.py            # http://127.0.0.1:5001
"""
import json
import os
import sqlite3
import sys

from flask import Flask, g, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

DB_PATH = os.path.join(BASE, "decrypted", "sns.sqlite")
MEDIA_DIR = os.path.join(BASE, "decrypted", "media_decrypted")
THUMB_DIR = MEDIA_DIR  # thumbnails live alongside full files (<stem>_t.<ext>)

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    return resp


def post_row(row):
    post = {
        "tid": row["tid"],
        "id": row["feed_id"],
        "username": row["username"],
        "nickname": row["nickname"],
        "create_time": row["create_time"],
        "create_time_str": row["create_time_str"],
        "content_desc": row["content_desc"],
        "content_type": row["content_type"],
        "content_type_name": row["content_type_name"],
        "is_private": bool(row["is_private"]),
        "location": json.loads(row["location"]) if row["location"] else None,
        "likes": json.loads(row["likes"]) if row["likes"] else [],
        "comments": json.loads(row["comments"]) if row["comments"] else [],
        "link_url": row["link_url"] or "",
        "link": (
            {
                "title": row["link_title"] or "",
                "description": row["link_description"] or "",
                "source": row["link_source"] or "",
                "thumb_url": row["link_thumb_url"] or "",
            }
            if (row["link_title"] or row["link_source"] or row["link_thumb_url"])
            else None
        ),
        "finder": json.loads(row["finder"]) if row["finder"] else None,
        "media": [],
    }
    return post


def attach_media(posts):
    """Attach each post's media list (resolved filenames) in one query."""
    if not posts:
        return
    db = get_db()
    placeholders = ",".join("?" for _ in posts)
    rows = db.execute(
        f"SELECT media_id, post_tid, media_index, mtype, width, height, file,"
        f" thumb_file FROM media WHERE post_tid IN ({placeholders}) ORDER BY media_index",
        [p["tid"] for p in posts],
    ).fetchall()
    by_post = {}
    for r in rows:
        by_post.setdefault(r["post_tid"], []).append({
            "media_id": r["media_id"],
            "type": r["mtype"],
            "width": r["width"],
            "height": r["height"],
            "file": r["file"],
            "thumb_file": r["thumb_file"] or "",
        })
    for p in posts:
        p["media"] = by_post.get(p["tid"], [])


@app.route("/api/posts")
def list_posts():
    page = max(1, request.args.get("page", 1, type=int))
    page_size = min(50, max(1, request.args.get("page_size", 10, type=int)))
    search = (request.args.get("search") or "").strip()

    db = get_db()
    where, params = "", []
    if search:
        like = f"%{search}%"
        where = (" WHERE content_desc LIKE ? OR nickname LIKE ?"
                 " OR username LIKE ?")
        params = [like, like, like]
    total = db.execute(
        f"SELECT count(*) FROM posts{where}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT * FROM posts{where} ORDER BY create_time DESC"
        f" LIMIT ? OFFSET ?",
        params + [page_size, (page - 1) * page_size],
    ).fetchall()
    posts = [post_row(r) for r in rows]
    attach_media(posts)
    return jsonify({
        "items": posts,
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": (total + page_size - 1) // page_size,
    })


@app.route("/api/posts/<path:tid>")
def get_post(tid):
    try:
        tid = int(tid)
    except ValueError:
        return jsonify({"error": "bad tid"}), 400
    db = get_db()
    row = db.execute("SELECT * FROM posts WHERE tid = ?", (tid,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    post = post_row(row)
    attach_media([post])
    return jsonify(post)


@app.route("/api/stats")
def stats():
    db = get_db()
    posts = db.execute("SELECT count(*) FROM posts").fetchone()[0]
    media = db.execute("SELECT count(*) FROM media WHERE file != ''").fetchone()[0]
    return jsonify({"posts": posts, "media": media})


@app.route("/media/<path:filename>")
def media(filename):
    return send_from_directory(MEDIA_DIR, filename)


@app.route("/media/finder-thumb/<feed_id>")
def finder_thumb(feed_id):
    """Serve the 视频号 (Channels) shared-video thumbnail, fetched + cached."""
    import urllib.request

    cached = os.path.join(MEDIA_DIR, f"{feed_id}_finder.jpg")
    if os.path.isfile(cached):
        return send_from_directory(MEDIA_DIR, os.path.basename(cached))

    db = get_db()
    row = db.execute("SELECT finder FROM posts WHERE feed_id = ?",
                     (feed_id,)).fetchone()
    if row is None or not row["finder"]:
        return jsonify({"error": "no finder"}), 404
    thumb_url = json.loads(row["finder"]).get("thumb_url", "")
    if not thumb_url:
        return jsonify({"error": "no thumb"}), 404
    url = thumb_url.replace("http://", "https://")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MicroMessenger Client"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        if len(data) < 100 or data[:3] != b"\xff\xd8\xff":
            return jsonify({"error": "bad thumb"}), 502
        with open(cached, "wb") as f:
            f.write(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    return send_from_directory(MEDIA_DIR, os.path.basename(cached))


@app.route("/media/link-card/<feed_id>")
def link_card_thumb(feed_id):
    """Serve the link-card cover image, fetched from the CDN and cached.

    The /150 thumbnail URLs in the post XML need no token and work without a
    special UA, but we still fetch with WeChat's UA and cache the file locally
    so the UI never depends on the CDN.
    """
    import urllib.request

    cached = os.path.join(MEDIA_DIR, f"{feed_id}_card.jpg")
    if os.path.isfile(cached):
        return send_from_directory(MEDIA_DIR, os.path.basename(cached))

    db = get_db()
    row = db.execute("SELECT link_thumb_url FROM posts WHERE feed_id = ?",
                     (feed_id,)).fetchone()
    if row is None or not row["link_thumb_url"]:
        return jsonify({"error": "no thumb"}), 404
    url = row["link_thumb_url"].replace("http://", "https://")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MicroMessenger Client"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
        if len(data) < 100 or data[:3] != b"\xff\xd8\xff":
            return jsonify({"error": "bad thumb"}), 502
        with open(cached, "wb") as f:
            f.write(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    return send_from_directory(MEDIA_DIR, os.path.basename(cached))


if __name__ == "__main__":
    if not os.path.isfile(DB_PATH):
        print(f"[ERROR] db not found: {DB_PATH}")
        print("  Run: .venv/bin/python backend/ingest.py")
        sys.exit(1)
    app.run(host="127.0.0.1", port=5001, debug=False)

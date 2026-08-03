"""
Export all WeChat SNS (Moments) data from the decrypted sns.db to plain JSON.

Output structure:
    {
      "exported_at": "...",
      "statistics": {...},
      "posts": [ ... each post parsed from the SnsDataItem XML ... ],
      "auxiliary_tables": { "SnsAdTimeLine": [...], "SnsTopItem_1": [...] }
    }

Comments and likes (SnsMessage_tmp3) are joined to posts via tid (feed_id).

Usage:
    python export_sns.py                          # decrypted/sns/sns.db -> sns_export.json
    python export_sns.py --db path/sns.db --output out.json
    python export_sns.py --no-raw                 # omit raw_xml from the output
"""
import argparse
import base64
import binascii
import datetime
import functools
import html
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET

print = functools.partial(print, flush=True)

# ── SNS content blob decoding ────────────────────────────────────────────────
# SnsTimeLine.content can be one of several encodings depending on WeChat
# version: zstd-compressed bytes, plain XML, hex string, or base64 string.
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# ── XML sanitization for old (2013-2017) dirty WeChat XML ───────────────────
# - bare & in URLs, bare < > inside text nodes, control characters
# CDATA blocks are left untouched.
_INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CDATA_BLOCK_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_BARE_AMP_RE = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
_TEXT_ONLY_NODES = (
    "content", "title", "description", "nickname", "contentDesc",
    "appname", "sourceName", "sourcename", "poiName", "displayName",
    "feeddesc",
)
_TEXT_NODE_RE = re.compile(
    r"(<(" + "|".join(_TEXT_ONLY_NODES) + r")\b[^>]*>)(.*?)(</\2>)",
    re.DOTALL,
)

# Content is untrusted input (posts from other users) — block XXE.
_UNSAFE_RE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
_MAX_XML_LEN = 200_000

_CONTENT_TYPES = {
    1: "image_text",
    2: "text",
    3: "link",
    5: "video_link",
    7: "location",
    15: "video",
    28: "short_video",
    30: "music",
    34: "note",
    42: "mini_program",
    54: "live",
}


def _decode_content_blob(value):
    """Decode SnsTimeLine.content (zstd bytes / plain XML / hex / base64) to XML text."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if raw.startswith(_ZSTD_MAGIC):
            try:
                import zstandard
                raw = zstandard.ZstdDecompressor().decompress(raw)
            except ImportError:
                pass
            except Exception:
                pass
        return html.unescape(raw.decode("utf-8", errors="ignore").strip())

    text = str(value).strip()
    if not text:
        return ""
    if text.lstrip().startswith("<"):
        return html.unescape(text)

    compact = "".join(text.split())
    if len(compact) >= 16 and len(compact) % 2 == 0 and _HEX_RE.match(compact):
        try:
            return _decode_content_blob(bytes.fromhex(compact))
        except ValueError:
            pass
    if len(compact) >= 24 and len(compact) % 4 == 0 and _BASE64_RE.match(compact):
        try:
            return _decode_content_blob(base64.b64decode(compact, validate=True))
        except (ValueError, binascii.Error):
            pass
    return html.unescape(text)


def _sanitize_xml(xml_text):
    """Repair old dirty WeChat XML so ElementTree can parse it."""
    s = _INVALID_CTRL_RE.sub("", xml_text)
    parts = []
    last = 0
    for m in _CDATA_BLOCK_RE.finditer(s):
        parts.append(_BARE_AMP_RE.sub("&amp;", s[last:m.start()]))
        parts.append(m.group(0))
        last = m.end()
    parts.append(_BARE_AMP_RE.sub("&amp;", s[last:]))
    out = "".join(parts)

    def _esc(m):
        return m.group(1) + m.group(3).replace("<", "&lt;").replace(">", "&gt;") + m.group(4)

    return _TEXT_NODE_RE.sub(_esc, out)


def _el_text(el, path, default=""):
    node = el.find(path)
    return node.text.strip() if node is not None and node.text else default


def _parse_media_list(timeline_obj):
    """Parse the media list inside TimelineObject."""
    medias = []
    for media_el in timeline_obj.findall(".//media"):
        info = {
            "id": _el_text(media_el, "id"),
            "type": _el_text(media_el, "type"),
            "sub_type": _el_text(media_el, "sub_type"),
            "video_duration": _el_text(media_el, "videoDuration", "0"),
        }
        thumb_el = media_el.find("thumb")
        if thumb_el is not None:
            info["thumb_url"] = thumb_el.text or ""
            for attr in ("key", "token", "enc_idx", "type"):
                info[f"thumb_{attr}"] = thumb_el.get(attr, "")
        url_el = media_el.find("url")
        if url_el is not None:
            info["url"] = url_el.text or ""
            for attr in ("key", "token", "enc_idx", "type", "md5"):
                info[f"url_{attr}"] = url_el.get(attr, "")
        size_el = media_el.find("size")
        if size_el is not None:
            info["width"] = size_el.get("width", "")
            info["height"] = size_el.get("height", "")
            info["total_size"] = size_el.get("totalSize", "")
        medias.append(info)
    return medias


def parse_timeline_xml(content_xml):
    """Parse one SnsTimeLine.content XML into a structured dict; None on failure."""
    if not content_xml:
        return None
    decoded = _decode_content_blob(content_xml)
    if not decoded or len(decoded) > _MAX_XML_LEN or _UNSAFE_RE.search(decoded):
        return None
    try:
        root = ET.fromstring(_sanitize_xml(decoded))
    except ET.ParseError:
        return None

    tl = root.find(".//TimelineObject")
    if tl is None:
        return None

    create_time_str = tl.findtext("createTime", "0")
    try:
        create_time = int(create_time_str)
    except ValueError:
        create_time = 0

    content_type_str = tl.findtext(".//ContentObject/type", "0")
    try:
        content_type = int(content_type_str)
    except ValueError:
        content_type = 0

    location = None
    loc_el = tl.find(".//location")
    if loc_el is not None:
        lat = loc_el.get("latitude", "0")
        lon = loc_el.get("longitude", "0")
        if lat != "0" or lon != "0":
            location = {
                "latitude": lat,
                "longitude": lon,
                "poi_name": loc_el.get("poiName", ""),
            }

    return {
        "id": tl.findtext("id", ""),
        "username": tl.findtext("username", ""),
        "create_time": create_time,
        "create_time_str": (
            datetime.datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
            if create_time else ""
        ),
        "content_desc": tl.findtext("contentDesc", ""),
        "content_type": content_type,
        "content_type_name": _CONTENT_TYPES.get(content_type, f"unknown({content_type})"),
        "nickname": root.findtext(".//LocalExtraInfo/nickname", ""),
        "is_private": tl.findtext("private", "0") == "1",
        "location": location,
        "media": _parse_media_list(tl),
        "link": _parse_link_card(tl, content_type),
        "finder": _parse_finder_feed(tl),
        "likes": _parse_user_comments(root, "like_user_list", 1),
        "comments": _parse_user_comments(root, "comment_user_list", 2),
    }


def _parse_user_comments(root, list_path, want_type):
    """Parse interactions embedded in the post XML.

    Every post carries its full like/comment list in the XML
    (like_user_list / comment_user_list). Replies reference their target via
    ref_comment_id / ref_username, so the target nickname is resolved from the
    comment list itself. Withdrawn interactions (b_deleted != 0) are skipped.
    """
    entries = []
    for uc in root.findall(f".//{list_path}/user_comment"):
        if (uc.findtext("b_deleted", "0") or "0") != "0":
            continue
        ctype = int(uc.findtext("type", "0") or 0)
        if ctype != want_type:
            continue
        ctime = int(uc.findtext("create_time", "0") or 0)
        entries.append({
            "comment_id": int(uc.findtext("comment_id", "0") or 0),
            "create_time": ctime,
            "create_time_str": (
                datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                if ctime else ""
            ),
            "type": ctype,
            "type_name": "like" if ctype == 1 else "comment",
            "username": uc.findtext("username", "") or "",
            "nickname": uc.findtext("nickname", "") or "",
            "to_username": uc.findtext("ref_username", "") or "",
            "to_nickname": "",
            "content": uc.findtext("content", "") or "",
            "ref_comment_id": int(uc.findtext("ref_comment_id", "0") or 0),
        })
    # resolve reply targets: ref_comment_id -> target nickname (only real replies)
    by_id = {e["comment_id"]: e["nickname"] for e in entries}
    for e in entries:
        if e["ref_comment_id"]:
            e["to_nickname"] = by_id.get(e["ref_comment_id"], "")
    return entries


def _parse_finder_feed(tl):
    """Flatten 视频号 (WeChat Channels) shared-video card info.

    These posts (content_type 28) carry a <finderFeed> with the account
    nickname, description, avatar and a media element whose thumbUrl is a
    downloadable thumbnail and url the actual video.
    """
    ff = tl.find(".//finderFeed")
    if ff is None:
        return None
    media = ff.find(".//media")
    return {
        "nickname": (ff.findtext("nickname") or "").strip(),
        "desc": (ff.findtext("desc") or "").strip(),
        "avatar": (ff.findtext("avatar") or "").strip(),
        "thumb_url": (media.findtext("thumbUrl") or "").strip() if media is not None else "",
        "video_url": (media.findtext("url") or "").strip() if media is not None else "",
    }


# content types that render a shared-link card in WeChat
_LINK_CARD_TYPES = {3, 5}


def _parse_link_card(tl, content_type):
    """Flatten the shared-link card info (link / video-link posts only).

    WeChat shows these as a card: title, description (e.g. "UP主: ...") and
    the source app ("来自 哔哩哔哩"). Extracted from ContentObject/description
    and appInfo/appName so the UI doesn't need the raw XML. Normal image/text
    posts must NOT get a card (their mediaList thumbs would match the generic
    selectors), hence the content_type gate.
    """
    if content_type not in _LINK_CARD_TYPES:
        return None
    title = (tl.findtext(".//ContentObject/title") or "").strip()
    desc = (tl.findtext(".//ContentObject/mediaList/media/description") or "").strip()
    source = (tl.findtext(".//appInfo/appName") or "").strip()
    thumb = (tl.findtext(".//ContentObject/mediaList/media/thumb") or "").strip()
    if not (title or desc or source or thumb):
        return None
    return {
        "title": title,
        "description": desc,
        "source": source,
        "thumb_url": thumb,
    }


def _load_interactions(conn):
    """Load likes/comments from SnsMessage_tmp3, grouped by feed_id (= tid).

    del_status != 0 means the interaction was withdrawn — skip those.
    """
    interactions = {}
    try:
        rows = conn.execute(
            "SELECT feed_id, create_time, type, from_username, from_nickname,"
            " to_username, to_nickname, content, comment_id"
            " FROM SnsMessage_tmp3 WHERE COALESCE(del_status, 0) = 0"
            " ORDER BY create_time"
        ).fetchall()
        for feed_id, ctime, ctype, from_u, from_n, to_u, to_n, content, comment_id in rows:
            item = {
                "create_time": ctime,
                "create_time_str": (
                    datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                    if ctime else ""
                ),
                "type": ctype,
                "type_name": "like" if ctype == 1 else "comment" if ctype == 2 else f"unknown({ctype})",
                "username": from_u or "",
                "nickname": from_n or "",
                "to_username": to_u or "",
                "to_nickname": to_n or "",
                "content": content or "",
                "comment_id": comment_id,
            }
            interactions.setdefault(feed_id, []).append(item)
    except Exception as e:
        print(f"[WARN] reading interactions failed: {e}")
    return interactions


def _json_value(v):
    """Convert sqlite values for JSON: bytes -> hex string."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    return v


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export WeChat SNS db to JSON")
    parser.add_argument("--db", default=os.path.join("decrypted", "sns", "sns.db"),
                        help="decrypted sns.db path (default: decrypted/sns/sns.db)")
    parser.add_argument("--output", default=os.path.join("decrypted", "sns_export.json"),
                        help="output JSON path (default: decrypted/sns_export.json)")
    parser.add_argument("--no-raw", action="store_true",
                        help="omit raw_xml from each post")
    parser.add_argument("--no-aux", action="store_true",
                        help="omit auxiliary tables (ads, top items, ...)")
    parser.add_argument("--only-mine", action="store_true",
                        help="only export posts authored by the account owner")
    parser.add_argument("--own-username",
                        help="your wxid for --only-mine (default: auto-detect "
                             "as the most frequent author)")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.db):
        print(f"[ERROR] db not found: {args.db}")
        print("  Run decrypt_db.py first to create the decrypted database.")
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    # Some columns are declared TEXT but hold binary junk (e.g. pack_info_buf);
    # decode leniently instead of raising on invalid UTF-8.
    conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
    try:
        interactions = _load_interactions(conn)

        posts = []
        parse_failures = 0
        rows = conn.execute(
            "SELECT tid, user_name, content, hex(pack_info_buf) FROM SnsTimeLine"
        ).fetchall()

        for tid, user_name, content, pack_info_buf in rows:
            parsed = parse_timeline_xml(content)
            if parsed is None:
                parse_failures += 1
                continue
            xml_likes = parsed.get("likes") or []
            xml_comments = parsed.get("comments") or []
            if xml_likes or xml_comments:
                # the XML carries the full interaction list
                likes, comments = xml_likes, xml_comments
            else:
                likes = [i for i in interactions.get(tid, []) if i["type"] == 1]
                comments = [i for i in interactions.get(tid, []) if i["type"] != 1]
            post = {
                "tid": tid,
                "id": parsed["id"],
                "username": parsed["username"] or user_name or "",
                "nickname": parsed["nickname"],
                "create_time": parsed["create_time"],
                "create_time_str": parsed["create_time_str"],
                "content_desc": parsed["content_desc"],
                "content_type": parsed["content_type"],
                "content_type_name": parsed["content_type_name"],
                "is_private": parsed["is_private"],
                "location": parsed["location"],
                "media": parsed["media"],
                "likes": likes,
                "comments": comments,
                "link": parsed.get("link"),
                "finder": parsed.get("finder"),
                "pack_info_buf": pack_info_buf or "",
            }
            if not args.no_raw:
                decoded = _decode_content_blob(content)
                post["raw_xml"] = decoded if decoded else content if content else ""
            posts.append(post)

        if args.only_mine:
            own = args.own_username or ""
            if not own:
                import collections
                own = collections.Counter(
                    p["username"] for p in posts if p["username"]
                ).most_common(1)[0][0]
            print(f"[+] only own posts (username={own})")
            posts = [p for p in posts if p["username"] == own]

        # stats are computed from the (possibly filtered) post list
        media_count = sum(len(p["media"]) for p in posts)
        loc_count = sum(1 for p in posts if p["location"])

        posts.sort(key=lambda p: p["create_time"], reverse=True)

        result = {
            "exported_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": {
                "posts": len(posts),
                "parse_failures": parse_failures,
                "media_items": media_count,
                "posts_with_location": loc_count,
                "likes": sum(len(p["likes"]) for p in posts),
                "comments": sum(len(p["comments"]) for p in posts),
            },
            "posts": posts,
        }

        if not args.no_aux:
            auxiliary = {}
            for table in ("SnsAdTimeLine", "SnsTopItem_1", "SnsMainTimeLineBreakFlag",
                          "SnsUserTimeLineBreakFlagV2", "SnsDraft", "SnsPublishTask",
                          "SnsErrorMessage", "SnsNoteVoice"):
                try:
                    col_names = [d[1] for d in conn.execute(f"PRAGMA table_info({table})")]
                    rows_t = conn.execute(f"SELECT * FROM {table}").fetchall()
                    if rows_t:
                        auxiliary[table] = [
                            {c: _json_value(v) for c, v in zip(col_names, row)}
                            for row in rows_t
                        ]
                except sqlite3.Error:
                    pass
            if auxiliary:
                result["auxiliary_tables"] = auxiliary

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    finally:
        conn.close()

    print(f"[+] exported {result['statistics']['posts']} posts"
          f" ({result['statistics']['media_items']} media,"
          f" {result['statistics']['comments']} comments,"
          f" {result['statistics']['likes']} likes,"
          f" {result['statistics']['posts_with_location']} with location)"
          f" -> {args.output}"
          f" ({os.path.getsize(args.output)/1024/1024:.1f} MB)")
    if result["statistics"]["parse_failures"]:
        print(f"[WARN] {result['statistics']['parse_failures']} rows failed to parse")
    return 0


if __name__ == "__main__":
    sys.exit(main())

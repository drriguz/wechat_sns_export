"""
Download all SNS media (images/videos) from the WeChat CDN.

Reads the media URLs from the JSON export (decrypted/sns_export.json) and
downloads each full image/video plus its thumbnail. Files are stored exactly
as received — CDN content is stream-encrypted (enc_idx=1), so it is saved
encrypted as .enc files (raw bytes are never altered).

Output layout (default: decrypted/media_cdn/):
    <media_id>.enc        full-size file
    <media_id>_t.enc      thumbnail
    download_manifest.json  per-file record: url, size, md5, checksum status

Caching / resume: an existing output file is skipped; the manifest is updated
incrementally, so re-running continues where it left off.

Checksums: the XML carries url_md5, but for encrypted content that is the md5
of the decrypted bytes and cannot be verified here — those entries are marked
"unverifiable". Plain (unencrypted) files are md5-verified against url_md5 and
marked ok/mismatch.

Usage:
    python download_media.py                          # default json + output
    python download_media.py --json path.json --output dir
    python download_media.py --workers 8 --only-full --no-thumbs
"""
import argparse
import functools
import hashlib
import http.client
import json
import os
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

print = functools.partial(print, flush=True)

DEFAULT_JSON = os.path.join("decrypted", "sns_export.json")
DEFAULT_OUTPUT = os.path.join("decrypted", "media_cdn")
MANIFEST_NAME = "download_manifest.json"

# Errors that re-runs should not retry (recorded in the manifest).
PERMANENT_ERRORS = ("no token", "no url", "non-http url", "too small")

RETRY_MAX = 3
RETRY_DELAY = 2
TIMEOUT = 30
USER_AGENT = "MicroMessenger Client"
MIN_FILE_SIZE = 50

_MAGICS = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG": "png",
    b"GIF8": "gif",
    b"RIFF": "webp",
    b"\x00\x00\x00": "mp4",  # ftyp box follows
}


def sniff_ext(data):
    """Detect file extension from magic bytes, or None if unrecognized."""
    for magic, ext in _MAGICS.items():
        if data.startswith(magic):
            if ext == "webp" and data[8:12] != b"WEBP":
                continue
            return ext
    return None


def build_url(raw_url, token):
    """Build the CDN URL.

    Two URL flavors exist:
    - mmsns.qpic.cn/.../0  -> requires appending token=<url_token>&idx=1
    - wxapp.tc.qq.com/...?<query> -> self-contained (token embedded in query),
      must be downloaded as-is; the mmsns append rule would break it.
    """
    url = raw_url.replace("http://", "https://") if raw_url else ""
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        return None
    if "?" in url:
        return url
    if not token:
        return None
    return f"{url}?token={token}&idx=1"


def download(url, retries=RETRY_MAX):
    """Download bytes; returns (data, error_str).

    https:// is attempted first (URLs are exported as http://); some CDN hosts
    have broken TLS, so SSL failures fall back to plain http once.
    """
    for attempt in range(retries):
        try:
            req = Request(url, headers={
                "User-Agent": USER_AGENT,
                "Referer": "https://weixin.qq.com/",
                "Accept": "*/*",
            })
            with urlopen(req, timeout=TIMEOUT) as resp:
                data = resp.read()
                if len(data) < MIN_FILE_SIZE:
                    # small bodies are JSON error pages (e.g. "No Privilege") —
                    # retrying won't help
                    return None, f"too small ({len(data)}B)"
                return data, None
        except HTTPError as e:
            if e.code == 400:
                return None, "400 expired token"
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
        except (URLError, TimeoutError, OSError, http.client.IncompleteRead,
                http.client.HTTPException, ssl.SSLError) as e:
            if url.startswith("https://"):
                # broken TLS on some CDN hosts — retry over plain http once
                return download(url.replace("https://", "http://", 1),
                                retries=retries)
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            else:
                return None, str(e)
    return None, "retries exhausted"


def collect_media_items(posts):
    """Flatten posts -> [(media_id, post_tid, full_src, thumb_src), ...]."""
    items = []
    seen = set()
    for post in posts:
        for idx, m in enumerate(post.get("media", [])):
            media_id = str(m.get("id") or "").strip()
            if not media_id or media_id in seen:
                media_id = f"{post['tid']}_{idx}"
            seen.add(media_id)
            full_src = {
                "url": m.get("url", ""),
                "token": m.get("url_token", ""),
                "enc_idx": m.get("url_enc_idx", "1"),
                "md5": m.get("url_md5", ""),
                "type": m.get("type", ""),
            }
            thumb_src = {
                "url": m.get("thumb_url", ""),
                "token": m.get("thumb_token", ""),
                "enc_idx": m.get("thumb_enc_idx", "1"),
                "md5": "",
                "type": m.get("type", ""),
            }
            items.append((media_id, post["tid"], full_src, thumb_src))
    return items


def checksum_status(data, src):
    """Validate md5 against url_md5 when possible.

    Returns (status, actual_md5): "ok" | "mismatch" | "unverifiable" | "n/a".
    """
    actual = hashlib.md5(data).hexdigest()
    expected = (src.get("md5") or "").strip()
    if not expected:
        return "n/a", actual
    if sniff_ext(data) is not None:
        # plaintext file — md5 must match the exported value
        return ("ok" if actual == expected else "mismatch"), actual
    # encrypted content: url_md5 is the md5 of the decrypted bytes
    return "unverifiable", actual


def save_one(src, media_id, suffix, output_dir, only_new, stats, lock):
    """Download + save one variant. Returns a manifest entry dict."""
    entry = {
        "media_id": media_id,
        "variant": "full" if not suffix else "thumb",
        "status": "fail",
        "error": "",
        "url": src.get("url", ""),
        "size": 0,
        "md5": "",
        "md5_expected": src.get("md5", "") or "",
        "checksum": "n/a",
    }
    if not src.get("url"):
        entry["error"] = "no url"
        return entry

    enc = str(src.get("enc_idx", "1"))
    ext = ".enc" if enc == "1" else ".bin"
    out_path = os.path.join(output_dir, f"{media_id}{suffix}{ext}")

    if only_new:
        # cache: skip if this variant was already downloaded (any extension)
        base = os.path.join(output_dir, f"{media_id}{suffix}")
        for cand in (out_path,) + tuple(
            base + e for e in (".enc", ".jpg", ".png", ".gif", ".webp", ".mp4", ".bin")
        ):
            if os.path.isfile(cand) and os.path.getsize(cand) > 0:
                entry["status"] = "skipped"
                entry["saved_path"] = cand
                entry["size"] = os.path.getsize(cand)
                entry["checksum"] = "n/a (cached)"
                with lock:
                    stats["skipped"] += 1
                return entry

    url = build_url(src.get("url", ""), src.get("token", ""))
    if not url:
        if not src.get("url"):
            entry["error"] = "no url"
        elif not src.get("url", "").startswith(("http://", "https://")):
            entry["error"] = "non-http url"
        else:
            entry["error"] = "no token"
        with lock:
            stats["fail"] += 1
        return entry

    data, err = download(url)
    if data is None:
        entry["error"] = err
        with lock:
            stats["fail"] += 1
        return entry

    check, md5 = checksum_status(data, src)
    entry.update(status="checksum_mismatch" if check == "mismatch" else "ok",
                 size=len(data), md5=md5, checksum=check)
    if check == "mismatch":
        entry["status"] = "checksum_mismatch"

    with lock:
        try:
            os.makedirs(output_dir, exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(data)
        except OSError as e:
            # e.g. disk full — record the failure, drop any partial file so a
            # later run can retry, and don't crash the whole download.
            try:
                if os.path.exists(out_path):
                    os.remove(out_path)
            except OSError:
                pass
            entry.update(status="fail", error=f"write: {e}", size=0, md5="",
                         checksum="n/a")
            stats["fail"] += 1
            return entry
        stats["ok"] += 1
        stats["bytes"] += len(data)
    entry["saved_path"] = out_path
    return entry


def load_manifest(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def main(argv=None):
    parser = argparse.ArgumentParser(description="Download WeChat SNS CDN media")
    parser.add_argument("--json", default=DEFAULT_JSON,
                        help=f"exported json (default: {DEFAULT_JSON})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"output dir (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--workers", type=int, default=4,
                        help="parallel download workers (default: 4)")
    parser.add_argument("--no-thumbs", action="store_true",
                        help="skip thumbnails, download full-size only")
    parser.add_argument("--force", action="store_true",
                        help="re-download even if a cached file exists")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.json):
        print(f"[ERROR] json not found: {args.json}")
        print("  Run export_sns.py first.")
        return 1

    with open(args.json, encoding="utf-8") as f:
        export = json.load(f)
    items = collect_media_items(export.get("posts", []))
    os.makedirs(args.output, exist_ok=True)

    manifest_path = os.path.join(args.output, MANIFEST_NAME)
    manifest = {e.get("media_id", "") + e.get("variant", ""): e
                for e in load_manifest(manifest_path)}
    lock = __import__("threading").Lock()
    stats = {"ok": 0, "skipped": 0, "fail": 0, "bytes": 0}

    print(f"[+] json: {args.json}")
    print(f"[+] {len(items)} media items"
          f" ({len(items) * (1 if args.no_thumbs else 2)} downloads),"
          f" workers={args.workers}, force={args.force}")
    print(f"[+] output: {os.path.abspath(args.output)}\n")

    tasks = []
    for media_id, post_tid, full_src, thumb_src in items:
        tasks.append((media_id, "", full_src))
        if not args.no_thumbs:
            tasks.append((media_id, "_t", thumb_src))

    # drop tasks that previously failed permanently
    prev = load_manifest(manifest_path)
    perm = {e["media_id"] + e["variant"]
            for e in prev if e["status"] == "fail" and e.get("error") in PERMANENT_ERRORS}
    if perm:
        kept = [t for t in tasks
                if t[0] + ("thumb" if t[1] == "_t" else "full") not in perm]
        print(f"[+] skipping {len(tasks) - len(kept)} known-undownloadable items"
              f" (no token / no url / error pages)")
        tasks = kept

    total = len(tasks)
    t0 = time.time()
    chunk = max(1, args.workers * 4)
    done = 0
    for start in range(0, total, chunk):
        batch = tasks[start:start + chunk]
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(
                save_one, src, media_id, suffix, args.output,
                only_new=not args.force, stats=stats, lock=lock)
                for media_id, suffix, src in batch]
            for f in futures:
                entry = f.result()
                manifest[entry["media_id"] + entry["variant"]] = entry
        done += len(batch)
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(sorted(manifest.values(), key=lambda e: e["media_id"]),
                      mf, ensure_ascii=False, indent=1)
        o, s, fl = stats["ok"], stats["skipped"], stats["fail"]
        print(f"  [{done}/{total}] ok={o} skip={s} fail={fl} "
              f"{stats['bytes']/1048576:.1f} MB ({time.time()-t0:.0f}s)")

    mm = sum(1 for e in manifest.values() if e["checksum"] == "mismatch")
    uv = sum(1 for e in manifest.values() if e["checksum"] == "unverifiable")
    el = time.time() - t0
    print(f"\nDone in {el:.0f}s")
    print(f"  downloaded: {stats['ok']}  ({stats['bytes']/1048576:.1f} MB)")
    print(f"  skipped (cached): {stats['skipped']}")
    print(f"  failed:    {stats['fail']}")
    print(f"  checksums: {mm} mismatch, {uv} unverifiable (encrypted)")
    print(f"  output:    {os.path.abspath(args.output)}")
    print(f"  manifest:  {manifest_path}")
    return 0


if __name__ == "__main__":
    main()

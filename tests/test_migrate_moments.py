"""Integration: WeChat export -> cryptowl vault migration.

Creates a small synthetic export (text post, image post, video post, link
post with finder, comments/likes), migrates it into a fresh vault, and
verifies rows, CWO1 file formats, and idempotent re-import.
"""

import json
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from Crypto.Cipher import AES

from vaultlib.crypto import hkdf_sha256
from vaultlib.vault import Vault

MASTER_PASSWORD = b"migration-test-password"
MAGIC = b"CWO1"
HEADER_LEN = 22
CHUNK_SIZE = 65536

NS = __import__("migrate_moments", fromlist=["uid"]).NS
import uuid


def uid(scope, key):
    return str(uuid.uuid5(NS, f"cryptowl:{scope}:{key}"))


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="migrate-test-")
        self.vault_dir = os.path.join(self.tmp, "personal")
        self.media_dir = os.path.join(self.tmp, "media")
        self.vault = Vault.create(self.vault_dir, MASTER_PASSWORD)
        self.vault.close()
        os.makedirs(self.media_dir)

        # tiny fake media files
        self.img_bytes = bytes(range(256)) * 8
        self.thumb_bytes = b"thumb-jpeg-bytes"
        self.video_bytes = (b"v" * CHUNK_SIZE) * 2 + b"tail"  # 2+ chunks
        open(os.path.join(self.media_dir, "1001.jpg"), "wb").write(self.img_bytes)
        open(os.path.join(self.media_dir, "1001_t.jpg"), "wb").write(self.thumb_bytes)
        open(os.path.join(self.media_dir, "2001.mp4"), "wb").write(self.video_bytes)
        open(os.path.join(self.media_dir, "2001_t.jpg"), "wb").write(self.thumb_bytes)

        self.export = {
            "exported_at": "2026-01-01T00:00:00",
            "posts": [
                {
                    "tid": 1, "id": "111", "username": "wxid_me", "nickname": "我",
                    "create_time": 1700000000, "content_desc": "hello world",
                    "content_type": 2, "is_private": True,
                    "likes": [{"username": "wxid_a", "nickname": "A",
                               "create_time": 1700000100}],
                },
                {
                    "tid": 2, "id": "222", "username": "wxid_me", "nickname": "我",
                    "create_time": 1700001000, "content_desc": "a photo",
                    "content_type": 1, "is_private": False,
                    "media": [{"id": "1001", "type": "2", "width": "1920",
                               "height": "1080"}],
                    "comments": [
                        {"username": "wxid_a", "nickname": "A", "content": "nice",
                         "comment_id": 11, "create_time": 1700001100},
                        {"username": "wxid_b", "nickname": "B", "content": "agree",
                         "comment_id": 12, "ref_comment_id": 11,
                         "create_time": 1700001200},
                    ],
                },
                {
                    "tid": 3, "id": "333", "username": "wxid_me", "nickname": "我",
                    "create_time": 1700002000, "content_desc": "a video",
                    "content_type": 15,
                    "media": [{"id": "2001", "type": "3", "width": "1280",
                               "height": "720", "video_duration": "3.5"}],
                },
                {
                    "tid": 4, "id": "444", "username": "wxid_me", "nickname": "我",
                    "create_time": 1700003000, "content_desc": "a finder",
                    "content_type": 28,
                    "finder": {"nickname": "云博优", "desc": "up", "video_url": "http://x"},
                },
            ],
        }
        self.export_path = os.path.join(self.tmp, "sns_export.json")
        with open(self.export_path, "w") as f:
            json.dump(self.export, f)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _migrate(self):
        with mock.patch("sys.argv", [
            "migrate_moments.py", "--vault", self.vault_dir,
            "--password", MASTER_PASSWORD.decode(),
            "--json", self.export_path,
            "--media", self.media_dir,
            "--schema", os.path.join(os.path.dirname(__file__), "..", "..",
                                     "cryptowl", "docs", "moments.sql"),
        ]):
            import migrate_moments
            return migrate_moments.main()

    def test_migrate_and_verify(self):
        self.assertEqual(self._migrate(), 0)

        with Vault.open(self.vault_dir, MASTER_PASSWORD) as v:
            moments = v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment WHERE deleted_at IS NULL")[0]
            self.assertEqual(moments, 4)

            # visibility mapping: is_private -> private, else friends
            rows = {r[0]: r[1] for r in v.conn.query(
                "SELECT source_id, visibility FROM t_moment")}
            self.assertEqual(rows["111"], "private")
            self.assertEqual(rows["222"], "friends")

            # source timestamps are epoch ms
            ts = v.conn.query_one(
                "SELECT source_created_at FROM t_moment WHERE source_id = '111'")[0]
            self.assertEqual(ts, 1700000000 * 1000)

            # comments + threading + counters
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_comment")[0], 2)
            parent = v.conn.query_one(
                "SELECT parent_id IS NOT NULL FROM t_moment_comment WHERE id = '"
                + uid("comment", "222:12") + "'")[0]
            self.assertEqual(parent, 1)
            cc = v.conn.query_one(
                "SELECT comment_count FROM t_moment WHERE source_id = '222'")[0]
            self.assertEqual(cc, 2)
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_like")[0], 1)

            # finder card
            card = v.conn.query_one(
                "SELECT card_type, author_name FROM t_moment_card")
            self.assertEqual(card[0], "finder")
            self.assertEqual(card[1], "云博优")

            # media rows
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_media")[0], 2)
            media = {r[0]: r[1:] for r in v.conn.query(
                "SELECT id, media_type, duration_ms FROM t_moment_media")}
            img_id = uid("media", "222:0")
            vid_id = uid("media", "333:0")
            self.assertEqual(media[img_id][0], "image")
            self.assertIsNone(media[img_id][1])
            self.assertEqual(media[vid_id][0], "video")
            self.assertEqual(media[vid_id][1], 3500)

        # -- verify encrypted files on disk ----------------------------------
        def decrypt_whole(path, aad):
            data = open(path, "rb").read()
            self.assertEqual(data[:4], MAGIC)
            version, chunk_size = struct.unpack(">HI", data[4:10])
            self.assertEqual(version, 1)
            self.assertEqual(chunk_size, 0)
            nonce = data[10:22]
            ct, tag = data[22:-16], data[-16:]
            fek = hkdf_sha256(self.vault.vault_key, b"", b"file", 32)
            c = AES.new(fek, AES.MODE_GCM, nonce=nonce)
            c.update(aad)
            return c.decrypt_and_verify(ct, tag)

        img_path = os.path.join(self.vault_dir, "attachments", img_id + ".cwo")
        thumb_path = os.path.join(self.vault_dir, "thumbnails", img_id + "_t.cwo")
        self.assertTrue(os.path.isfile(img_path))
        self.assertTrue(os.path.isfile(thumb_path))
        self.assertEqual(decrypt_whole(img_path, img_id.encode("ascii")), self.img_bytes)
        self.assertEqual(decrypt_whole(thumb_path, img_id.encode("ascii")), self.thumb_bytes)

        # video: chunked layout — header has chunk_size 65536 and count 3
        vid_path = os.path.join(self.vault_dir, "attachments", vid_id + ".cwo")
        data = open(vid_path, "rb").read()
        version, chunk_size = struct.unpack(">HI", data[4:10])
        count = struct.unpack(">Q", data[10:18])[0]
        self.assertEqual((version, chunk_size), (1, CHUNK_SIZE))
        self.assertEqual(count, 3)
        # ciphertext + 16 B tag per chunk; the last chunk may be partial
        self.assertEqual(len(data), HEADER_LEN + len(self.video_bytes) + 16 * count)
        # decrypt every chunk with nonce = u64(i) || iv_prefix, AAD = media id
        iv_prefix = data[18:22]
        fek = hkdf_sha256(self.vault.vault_key, b"", b"file", 32)
        plain = b""
        total_ct = len(data) - HEADER_LEN - 16 * count
        for i in range(count):
            chunk_len = min(CHUNK_SIZE, total_ct - i * CHUNK_SIZE)
            off = HEADER_LEN + i * (CHUNK_SIZE + 16)
            chunk_ct = data[off:off + chunk_len]
            chunk_tag = data[off + chunk_len:off + chunk_len + 16]
            c = AES.new(fek, AES.MODE_GCM, nonce=i.to_bytes(8, "big") + iv_prefix)
            c.update(vid_id.encode("ascii"))
            plain += c.decrypt_and_verify(chunk_ct, chunk_tag)
        self.assertEqual(plain, self.video_bytes)

    def test_reimport_is_idempotent(self):
        self._migrate()
        self._migrate()
        with Vault.open(self.vault_dir, MASTER_PASSWORD) as v:
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment")[0], 4)
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_media")[0], 2)
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_comment")[0], 2)
            self.assertEqual(v.conn.query_one(
                "SELECT COUNT(*) FROM t_moment_like")[0], 1)
            # denormalized counters survive re-import
            self.assertEqual(v.conn.query_one(
                "SELECT comment_count FROM t_moment WHERE source_id = '222'")[0], 2)
            self.assertEqual(v.conn.query_one(
                "SELECT like_count FROM t_moment WHERE source_id = '111'")[0], 1)


if __name__ == "__main__":
    unittest.main()

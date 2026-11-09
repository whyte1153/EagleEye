"""Forensics engine tests.  Pure Python (no Django); run alone with
    python -m unittest apps.forensics.tests.test_engine -v
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from apps.forensics.engine import custody
from apps.forensics.engine.filetype import analyze_file, check_extension, detect, shannon_entropy
from apps.forensics.engine.hashing import hash_path
from apps.forensics.engine.sanitize import extension_of, safe_display_name
from apps.forensics.engine.storage import (EmptyFile, EvidenceStore, IntegrityError, TooLarge, UnsafeStorage)


def chunks(data: bytes, size: int = 7):
    for i in range(0, len(data), size):
        yield data[i:i + size]


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.store = EvidenceStore(self.tmp / "store")

    def tearDown(self):
        # originals are read-only; make writable so cleanup works
        for p in (self.tmp / "store").rglob("*"):
            try:
                os.chmod(p, 0o700)
            except OSError:
                pass
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.tmp / name
        p.write_bytes(data)
        return p


class SanitizeTests(unittest.TestCase):
    def test_strips_paths_and_controls(self):
        self.assertEqual(safe_display_name("../../etc/passwd"), "passwd")
        self.assertEqual(safe_display_name("C:\\Users\\bob\\report.pdf"), "report.pdf")
        self.assertEqual(safe_display_name("a\x00b\nc.txt"), "abc.txt")
        self.assertEqual(safe_display_name(""), "unnamed")
        self.assertEqual(safe_display_name("..."), "unnamed")

    def test_bidi_override_extension_spoof_removed(self):
        spoof = "invoice\u202egpj.exe"
        cleaned = safe_display_name(spoof)
        self.assertNotIn("\u202e", cleaned)
        self.assertEqual(extension_of(spoof), "exe")

    def test_long_names_keep_extension(self):
        name = safe_display_name("a" * 500 + ".pdf")
        self.assertLessEqual(len(name), 200)
        self.assertTrue(name.endswith(".pdf"))

    def test_extension(self):
        self.assertEqual(extension_of("Photo.JPG"), "jpg")
        self.assertEqual(extension_of("archive.tar.gz"), "gz")
        self.assertEqual(extension_of("README"), "")
        self.assertEqual(extension_of(".bashrc"), "")


class HashingTests(TmpCase):
    def test_known_vectors(self):
        h = hash_path(self.write("a", b"abc"))
        self.assertEqual(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(h.md5, "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(h.size, 3)

    def test_large_multi_chunk(self):
        data = os.urandom(3 * 1024 * 1024 + 17)
        self.assertEqual(hash_path(self.write("big", data)).sha256, hashlib.sha256(data).hexdigest())


class StorageTests(TmpCase):
    def test_ingest_hashes_and_stores_read_only(self):
        data = b"evidence bytes" * 1000
        stored = self.store.ingest(chunks(data, 100), 10_000_000)
        self.assertEqual(stored.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(stored.size, len(data))
        path = self.store.path(stored.name)
        self.assertEqual(path.read_bytes(), data)
        mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode, 0o440)  # read-only
        self.assertEqual(list((self.tmp / "store" / "incoming").iterdir()), [])  # temp file cleaned

    def test_stored_name_is_random_and_ignores_user_input(self):
        a = self.store.ingest(chunks(b"x"), 100)
        b = self.store.ingest(chunks(b"x"), 100)
        self.assertNotEqual(a.name, b.name)
        self.assertRegex(a.name, r"^[0-9a-f]{32}$")

    def test_size_limit_enforced_and_cleaned_up(self):
        with self.assertRaises(TooLarge):
            self.store.ingest(chunks(b"A" * 5000, 500), 1000)
        self.assertEqual(list((self.tmp / "store" / "incoming").iterdir()), [])
        self.assertEqual(list((self.tmp / "store" / "originals").rglob("*")), [])

    def test_empty_file_rejected(self):
        with self.assertRaises(EmptyFile):
            self.store.ingest(iter([]), 100)

    def test_error_midstream_leaves_nothing(self):
        def bad():
            yield b"abc"
            raise IOError("disk went away")
        with self.assertRaises(IOError):
            self.store.ingest(bad(), 100)
        self.assertEqual(list((self.tmp / "store" / "incoming").iterdir()), [])

    def test_path_traversal_names_rejected(self):
        for name in ("../../etc/passwd", "..", "a" * 32 + "/x", "ZZ" * 16, "", "abc", "A" * 32, "a" * 31):
            with self.subTest(name=name), self.assertRaises(UnsafeStorage):
                self.store.path(name)

    def test_verify_detects_tampering_and_missing(self):
        stored = self.store.ingest(chunks(b"original content"), 1000)
        self.assertEqual(self.store.verify(stored.name, stored.sha256).status, "verified")
        path = self.store.path(stored.name)
        os.chmod(path, 0o600)
        path.write_bytes(b"original contenT")  # one-byte change
        result = self.store.verify(stored.name, stored.sha256)
        self.assertEqual(result.status, "failed")
        self.assertNotEqual(result.actual_sha256, stored.sha256)
        path.unlink()
        self.assertEqual(self.store.verify(stored.name, stored.sha256).status, "missing")

    def test_symlink_is_not_trusted(self):
        stored = self.store.ingest(chunks(b"data"), 100)
        outside = self.write("outside", b"data")
        path = self.store.path(stored.name)
        os.chmod(path, 0o600)
        path.unlink()
        path.symlink_to(outside)
        self.assertEqual(self.store.verify(stored.name, stored.sha256).status, "missing")
        self.assertFalse(self.store.exists(stored.name))

    def test_working_copy_is_identical_and_deleted_afterwards(self):
        stored = self.store.ingest(chunks(b"payload" * 100), 100000)
        with self.store.working_copy(stored.name, stored.sha256) as wc:
            self.assertEqual(wc.read_bytes(), b"payload" * 100)
            self.assertNotEqual(wc, self.store.path(stored.name))  # analysis never touches the original
            copy_dir = wc.parent
        self.assertFalse(copy_dir.exists())
        self.assertEqual(self.store.path(stored.name).read_bytes(), b"payload" * 100)

    def test_working_copy_refused_if_original_changed(self):
        stored = self.store.ingest(chunks(b"payload"), 1000)
        path = self.store.path(stored.name)
        os.chmod(path, 0o600)
        path.write_bytes(b"tampered")
        with self.assertRaises(IntegrityError):
            with self.store.working_copy(stored.name, stored.sha256):
                self.fail("must not yield")
        self.assertEqual(list((self.tmp / "store" / "working").iterdir()), [])

    def test_working_copy_cleaned_up_even_if_analysis_raises(self):
        stored = self.store.ingest(chunks(b"payload"), 1000)
        with self.assertRaises(RuntimeError):
            with self.store.working_copy(stored.name, stored.sha256):
                raise RuntimeError("boom")
        self.assertEqual(list((self.tmp / "store" / "working").iterdir()), [])

    def test_root_inside_web_directory_is_refused(self):
        static = self.tmp / "static"
        static.mkdir()
        with self.assertRaises(UnsafeStorage):
            EvidenceStore(static / "evidence", forbidden_roots=[static])
        EvidenceStore(self.tmp / "ok", forbidden_roots=[static])  # fine

    def test_store_root_is_private(self):
        self.assertEqual(stat.S_IMODE((self.tmp / "store").stat().st_mode), 0o700)


class CustodyChainTests(unittest.TestCase):
    def make(self, n=4):
        entries, prev = [], custody.GENESIS
        for i in range(n):
            e = {"evidence_id": "EV-2026-000001", "action": f"act{i}", "actor": "alice", "detail": f"d{i}",
                 "created_iso": f"2026-11-03T08:0{i}:00+00:00", "ip": "127.0.0.1", "prev_hash": prev}
            e["entry_hash"] = custody.compute_entry_hash(prev, e["evidence_id"], e["action"], e["actor"], e["detail"],
                                                         e["created_iso"], e["ip"])
            prev = e["entry_hash"]
            entries.append(e)
        return entries

    def test_valid_chain(self):
        ok, bad, msg = custody.verify_chain(self.make())
        self.assertTrue(ok)
        self.assertIsNone(bad)

    def test_empty_chain_is_valid(self):
        self.assertTrue(custody.verify_chain([])[0])

    def test_edit_detected(self):
        entries = self.make()
        entries[1]["detail"] = "edited"
        ok, bad, _ = custody.verify_chain(entries)
        self.assertEqual((ok, bad), (False, 1))

    def test_deletion_detected(self):
        entries = self.make()
        del entries[1]
        ok, bad, _ = custody.verify_chain(entries)
        self.assertEqual((ok, bad), (False, 1))

    def test_reorder_detected(self):
        entries = self.make()
        entries[1], entries[2] = entries[2], entries[1]
        self.assertFalse(custody.verify_chain(entries)[0])

    def test_truncating_the_tail_is_not_detectable_without_an_external_anchor(self):
        # Documented limitation: dropping the LAST entries leaves a valid shorter chain.
        self.assertTrue(custody.verify_chain(self.make()[:-1])[0])

    def test_first_entry_must_link_to_genesis(self):
        entries = self.make()
        entries[0]["prev_hash"] = "f" * 64
        self.assertEqual(custody.verify_chain(entries)[1], 0)


class FileTypeTests(TmpCase):
    PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + struct.pack(">II", 640, 480) + b"\x08\x06\x00\x00\x00"
    PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 30

    def analyze(self, name, data):
        p = self.write("f.bin", data)
        return analyze_file(p, name, len(data))

    def test_matches(self):
        for name, data, kind in [
            ("a.png", self.PNG, "png"), ("b.jpg", b"\xff\xd8\xff\xe0" + b"\0" * 30, "jpeg"),
            ("c.pdf", b"%PDF-1.4\n", "pdf"), ("d.gif", b"GIF89a" + b"\0" * 10, "gif"),
            ("e.gz", b"\x1f\x8b\x08" + b"\0" * 10, "gzip"), ("f.sqlite", b"SQLite format 3\x00" + b"\0" * 20, "sqlite"),
            ("g.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 20, "pcap"), ("h.txt", b"plain text\n", "text"),
            ("i.json", b'{"a": 1}', "json"), ("j.html", b"<!DOCTYPE html><html></html>", "html"),
            ("k.xml", b"<?xml version='1.0'?><a/>", "xml"), ("l.exe", self.PE, "pe"),
            ("m.sh", b"#!/bin/sh\necho hi\n", "script"), ("n.mp4", b"\0\0\0\x18ftypmp42" + b"\0" * 12, "mp4"),
            ("o.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"), ("p.wav", b"RIFF\x00\x00\x00\x00WAVEfmt ", "wav"),
        ]:
            with self.subTest(name=name):
                r = self.analyze(name, data)
                self.assertEqual(r["detected_kind"], kind)
                self.assertEqual(r["extension_severity"], "match", r["extension_note"])
                self.assertFalse(r["mismatch"])

    def test_executable_disguised_as_image_is_high(self):
        r = self.analyze("holiday.jpg", self.PE)
        self.assertEqual((r["detected_kind"], r["extension_severity"], r["mismatch"]), ("pe", "high", True))

    def test_elf_without_extension_is_fine(self):
        self.assertEqual(self.analyze("tool", b"\x7fELF\x02\x01\x01" + b"\0" * 30)["extension_severity"], "match")

    def test_pe_without_extension_is_high(self):
        self.assertEqual(self.analyze("tool", self.PE)["extension_severity"], "high")

    def test_script_disguised_as_document(self):
        self.assertEqual(self.analyze("report.pdf", b"#!/bin/sh\nrm -rf /\n")["extension_severity"], "high")

    def test_renamed_file_warns(self):
        r = self.analyze("photo.png", b"%PDF-1.7\n")
        self.assertEqual((r["extension_severity"], r["mismatch"]), ("warn", True))

    def test_text_posing_as_image_warns(self):
        self.assertEqual(self.analyze("pic.png", b"just words, no image\n")["extension_severity"], "warn")

    def test_binary_posing_as_text_warns(self):
        self.assertEqual(self.analyze("notes.txt", bytes(range(256)) * 4)["extension_severity"], "warn")

    def test_unrecognised_binary_with_unknown_extension_is_info(self):
        r = self.analyze("blob.xyz", bytes(range(256)) * 4)
        self.assertEqual((r["detected_kind"], r["extension_severity"]), ("unrecognised", "info"))

    def test_unrecognised_with_known_extension_warns(self):
        self.assertEqual(self.analyze("broken.png", bytes(range(256)) * 4)["extension_severity"], "warn")

    def test_no_extension_is_info(self):
        self.assertEqual(self.analyze("README", b"%PDF-1.4\n")["extension_severity"], "info")

    def test_empty_head_is_unrecognised_not_a_crash(self):
        self.assertIsNone(detect(self.write("e", b"")))

    def test_office_zip_and_mismatch(self):
        p = self.tmp / "d.docx"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("[Content_Types].xml", "x")
            z.writestr("word/document.xml", "x")
            z.writestr("../../evil.sh", "x")
            z.writestr("/abs/path", "x")
        r = analyze_file(p, "d.docx", p.stat().st_size)
        self.assertEqual((r["detected_kind"], r["extension_severity"]), ("docx", "match"))
        self.assertEqual(r["metadata"]["suspicious_paths"], 2)
        self.assertEqual(r["metadata"]["entry_count"], 4)
        self.assertEqual(analyze_file(p, "d.xlsx", p.stat().st_size)["extension_severity"], "warn")
        self.assertEqual(analyze_file(p, "d.zip", p.stat().st_size)["extension_severity"], "info")

    def test_plain_zip_with_docx_extension_is_accepted_as_generic_container(self):
        p = self.tmp / "z.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("a.txt", "x")
        self.assertEqual(analyze_file(p, "z.zip", p.stat().st_size)["extension_severity"], "match")
        self.assertEqual(analyze_file(p, "z.docx", p.stat().st_size)["extension_severity"], "match")

    def test_corrupt_zip_does_not_crash(self):
        r = self.analyze("broken.zip", b"PK\x03\x04" + os.urandom(200))
        self.assertIn("listing_error", r["metadata"])

    def test_zip_entry_names_are_sanitised_for_display(self):
        p = self.tmp / "n.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("dir/ev\u202eil.txt", "x")
        names = [e["name"] for e in analyze_file(p, "n.zip", p.stat().st_size)["metadata"]["entries"]]
        self.assertTrue(all("\u202e" not in n for n in names))

    def test_png_dimensions_and_pdf_version(self):
        self.assertEqual(self.analyze("a.png", self.PNG)["metadata"]["width"], 640)
        self.assertEqual(self.analyze("a.pdf", b"%PDF-1.7\n%%EOF\n")["metadata"]["pdf_version"], "1.7")

    def test_metadata_has_header_entropy_and_timestamp_caveat(self):
        p = self.write("t.bin", b"hello")
        r = analyze_file(p, "t.txt", 5, {"stored_modified": "x"})
        self.assertEqual(r["metadata"]["header_hex"], "68 65 6c 6c 6f")
        self.assertIn("timestamp_caveat", r["metadata"])
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8.0, places=2)

    def test_nothing_is_executed_or_modified(self):
        p = self.write("run.sh", b"#!/bin/sh\ntouch " + str(self.tmp / "pwned").encode() + b"\n")
        os.chmod(p, 0o755)
        before = hash_path(p).sha256
        analyze_file(p, "run.sh", p.stat().st_size)
        self.assertFalse((self.tmp / "pwned").exists())
        self.assertEqual(hash_path(p).sha256, before)

    def test_check_extension_directly(self):
        self.assertEqual(check_extension("x.exe", None)[0], "warn")


if __name__ == "__main__":
    unittest.main()

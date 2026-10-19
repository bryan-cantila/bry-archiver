"""Tests for bry-archiver: format, CLI, and corruption handling."""

import os
import struct
import unittest

from bry import cli, format as bf


def make_tree(root):
    os.makedirs(os.path.join(root, "docs", "nested"), exist_ok=True)
    with open(os.path.join(root, "hello.txt"), "w") as fh:
        fh.write("hello bry\n" * 100)
    with open(os.path.join(root, "docs", "nested", "data.bin"), "wb") as fh:
        fh.write(bytes(range(256)) * 64)
    with open(os.path.join(root, "empty.txt"), "w") as fh:
        pass
    with open(os.path.join(root, "caf\u00e9-\u65e5\u672c.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("unicode filename round-trip\n")


def _v3_layout(path):
    """Return (raw, comp_stream_off, raw_stream_off) for a v3 archive."""
    with open(path, "rb") as fh:
        raw = fh.read()
    assert raw[:4] == b"BRY\x03", "expected a v3 archive"
    count = struct.unpack(">I", raw[6:10])[0]
    off = 10  # magic(4) + flags(1) + method(1) + file_count(4)
    for _ in range(count):
        name_len = struct.unpack(">H", raw[off:off + 2])[0]
        off += 31 + name_len  # entry meta (31) + name
    comp_len = struct.unpack(">Q", raw[off:off + 8])[0]
    comp_off = off + 8
    return raw, comp_off, comp_off + comp_len


def corrupt_stream_byte(path):
    """Flip one byte inside the v3 compressed stream."""
    raw, comp_off, raw_off = _v3_layout(path)
    raw = bytearray(raw)
    # stay clear of the 13-byte LZMA ALONE header; hit the coded data
    pos = comp_off + 13 + (raw_off - comp_off - 13) // 2
    raw[pos] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


def corrupt_crc_byte(path):
    """Flip one byte of the first *file* entry's stored CRC32 (v3 index)."""
    raw, _comp_off, _raw_off = _v3_layout(path)
    raw = bytearray(raw)
    count = struct.unpack(">I", raw[6:10])[0]
    off = 10
    for _ in range(count):
        name_len = struct.unpack(">H", raw[off:off + 2])[0]
        name = raw[off + 31:off + 31 + name_len].decode("utf-8")
        if not name.endswith("/"):  # first real file entry
            crc_off = off + 2 + 8 + 8  # name_len + orig_size + offset
            raw[crc_off] ^= 0xFF
            break
        off += 31 + name_len
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


def pack_v2(files, out):
    """Minimal v2 writer (BRY\\x02, solid LZMA) for backward-compat tests."""
    import lzma
    import zlib
    names = sorted(files)
    solid = bytearray()
    metas = []
    for name in names:
        data = files[name]
        metas.append((name, len(data), len(solid), zlib.crc32(data) & 0xFFFFFFFF))
        solid += data
    comp = lzma.compress(bytes(solid), preset=6, format=lzma.FORMAT_ALONE)
    with open(out, "wb") as fh:
        fh.write(struct.pack(">4sBBI", b"BRY\x02", 0, 1, len(names)))
        for name, size, offset, crc in metas:
            nb = name.encode("utf-8")
            fh.write(struct.pack(">HQQIQ", len(nb), size, offset, crc, 0))
            fh.write(nb)
        fh.write(comp)



def pack_v1(files, out):
    """Minimal v1 writer (BRY\\x01, per-file zlib) for backward-compat tests."""
    import zlib
    names = sorted(files)
    with open(out, "wb") as fh:
        fh.write(struct.pack(">4sBI", b"BRY\x01", 0, len(names)))
        for name in names:
            data = files[name]
            comp = zlib.compress(data, 6)
            crc = zlib.crc32(data) & 0xFFFFFFFF
            nb = name.encode("utf-8")
            fh.write(struct.pack(">HQQIq", len(nb), len(data), len(comp), crc, 0))
            fh.write(nb)
            fh.write(comp)


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.abspath("test_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        make_tree(self.src)
        self.arc = os.path.join(self.tmp, "out.bry")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pack_unpack(self, level=6):
        bf.pack([self.src], self.arc, level=level)
        dest = os.path.join(self.tmp, "dest")
        n = bf.unpack(self.arc, dest)
        return dest, n

    def _tree_files(self, root):
        got = {}
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                full = os.path.join(dirpath, f)
                with open(full, "rb") as fh:
                    got[os.path.relpath(full, root)] = fh.read()
        return got

    def test_text_and_binary_round_trip(self):
        dest, _n = self._pack_unpack()
        base = os.path.basename(self.src)
        self.assertEqual(self._tree_files(self.src),
                         self._tree_files(os.path.join(dest, base)))

    def test_empty_file_preserved(self):
        dest, _n = self._pack_unpack()
        p = os.path.join(dest, os.path.basename(self.src), "empty.txt")
        self.assertTrue(os.path.isfile(p))
        self.assertEqual(os.path.getsize(p), 0)

    def test_nested_directories_preserved(self):
        entries = bf.list_entries(self.arc) if os.path.exists(self.arc) else None
        dest, _n = self._pack_unpack()
        base = os.path.basename(self.src)
        nested = os.path.join(dest, base, "docs", "nested", "data.bin")
        self.assertTrue(os.path.isfile(nested))
        with open(nested, "rb") as fh:
            self.assertEqual(fh.read(), bytes(range(256)) * 64)
        self.assertTrue(os.path.isdir(os.path.join(dest, base, "docs", "nested")))

    def test_unicode_filename(self):
        dest, _n = self._pack_unpack()
        base = os.path.basename(self.src)
        names = os.listdir(os.path.join(dest, base))
        self.assertIn("caf\u00e9-\u65e5\u672c.txt", names)

    def test_magic_bytes(self):
        bf.pack([self.src], self.arc)
        with open(self.arc, "rb") as fh:
            self.assertEqual(fh.read(4), b"BRY\x03")

    def test_level_1_and_9_round_trip(self):
        for level in (1, 9):
            arc = os.path.join(self.tmp, "l%d.bry" % level)
            bf.pack([self.src], arc, level=level)
            dest = os.path.join(self.tmp, "d%d" % level)
            bf.unpack(arc, dest)
            base = os.path.basename(self.src)
            self.assertEqual(self._tree_files(self.src),
                             self._tree_files(os.path.join(dest, base)))

    def test_level_9_not_larger_than_level_1(self):
        # use a bigger redundant tree so LZMA levels actually differ
        bigsrc = os.path.join(self.tmp, "bigsrc")
        os.makedirs(bigsrc)
        chunk = ("the quick brown fox jumps over the lazy dog. " * 200 + "\n").encode()
        for i in range(10):
            with open(os.path.join(bigsrc, "f%02d.txt" % i), "wb") as fh:
                fh.write(chunk)
        a1 = os.path.join(self.tmp, "a1.bry")
        a9 = os.path.join(self.tmp, "a9.bry")
        bf.pack([bigsrc], a1, level=1)
        bf.pack([bigsrc], a9, level=9)
        self.assertLessEqual(os.path.getsize(a9), os.path.getsize(a1))

    def test_verify_clean_archive(self):
        bf.pack([self.src], self.arc)
        self.assertEqual(bf.verify(self.arc), [])

    def test_list_entries(self):
        bf.pack([self.src], self.arc)
        entries = bf.list_entries(self.arc)
        names = [e.name for e in entries]
        base = os.path.basename(self.src)
        self.assertIn(base + "/", names)
        self.assertIn(base + "/hello.txt", names)
        self.assertTrue(any(e.is_dir for e in entries))


class TestCorruption(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.abspath("ctest_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "victim.txt"), "w") as fh:
            fh.write("important data\n" * 50)
        self.arc = os.path.join(self.tmp, "out.bry")
        bf.pack([self.src], self.arc)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_corrupt_stream_byte_fails_verify(self):
        corrupt_stream_byte(self.arc)
        problems = bf.verify(self.arc)
        self.assertEqual(len(problems), 1)
        self.assertIn("data stream", problems[0])

    def test_corrupt_stream_byte_fails_unpack(self):
        corrupt_stream_byte(self.arc)
        with self.assertRaises(bf.CorruptArchive):
            bf.unpack(self.arc, os.path.join(self.tmp, "dest"))

    def test_corrupt_crc_byte_names_file(self):
        corrupt_crc_byte(self.arc)
        problems = bf.verify(self.arc)
        self.assertEqual(len(problems), 1)
        self.assertIn("victim.txt", problems[0])

    def test_wrong_magic_rejected(self):
        bad = os.path.join(self.tmp, "bad.bry")
        with open(bad, "wb") as fh:
            fh.write(b"ZIP\x02" + b"\x00" * 32)
        with self.assertRaises(bf.NotABryArchive) as ctx:
            bf.list_entries(bad)
        self.assertIn("not a .bry archive", str(ctx.exception))

    def test_truncated_archive_rejected(self):
        bf.pack([self.src], self.arc)
        with open(self.arc, "rb") as fh:
            data = fh.read()
        bad = os.path.join(self.tmp, "trunc.bry")
        with open(bad, "wb") as fh:
            fh.write(data[:20])
        problems = bf.verify(bad)
        self.assertTrue(problems, "truncated archive should not verify clean")


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.abspath("cli_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "a.txt"), "w") as fh:
            fh.write("cli test\n")
        self.arc = os.path.join(self.tmp, "cli.bry")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cli_pack_list_verify_unpack(self):
        self.assertEqual(
            cli.main(["pack", self.src, "-o", self.arc, "--level", "9"]), 0)
        self.assertEqual(cli.main(["verify", self.arc]), 0)
        self.assertEqual(cli.main(["list", self.arc]), 0)
        dest = os.path.join(self.tmp, "out")
        self.assertEqual(cli.main(["unpack", self.arc, "-d", dest]), 0)
        self.assertTrue(os.path.isfile(
            os.path.join(dest, "src", "a.txt")))

    def test_cli_verify_bad_file_fails(self):
        bad = os.path.join(self.tmp, "bad.bry")
        with open(bad, "wb") as fh:
            fh.write(b"nope")
        self.assertEqual(cli.main(["verify", bad]), 1)

    def test_cli_pack_missing_input_fails(self):
        self.assertEqual(
            cli.main(["pack", os.path.join(self.tmp, "nope"), "-o", self.arc]), 1)


class TestV1BackwardCompat(unittest.TestCase):
    """v1 archives (per-file zlib) must remain listable/verifiable/unpackable."""

    def setUp(self):
        self.tmp = os.path.abspath("v1compat_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.arc = os.path.join(self.tmp, "old.bry")
        self.files = {
            "readme.txt": b"hello v1\n" * 20,
            "sub/data.bin": bytes(range(256)) * 10,
            "empty.txt": b"",
        }
        pack_v1(self.files, self.arc)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v1_list(self):
        names = sorted(e.name for e in bf.list_entries(self.arc))
        self.assertEqual(names, sorted(self.files))

    def test_v1_verify_clean(self):
        self.assertEqual(bf.verify(self.arc), [])

    def test_v1_unpack_round_trip(self):
        dest = os.path.join(self.tmp, "dest")
        n = bf.unpack(self.arc, dest)
        self.assertEqual(n, len(self.files))
        for name, data in self.files.items():
            with open(os.path.join(dest, *name.split("/")), "rb") as fh:
                self.assertEqual(fh.read(), data)


class TestV2BackwardCompat(unittest.TestCase):
    """v2 archives (BRY\\x02, solid LZMA) must remain listable/verifiable/unpackable."""

    def setUp(self):
        self.tmp = os.path.abspath("v2compat_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.arc = os.path.join(self.tmp, "v2.bry")
        self.files = {
            "readme.txt": b"hello v2\n" * 20,
            "sub/data.bin": bytes(range(256)) * 10,
        }
        pack_v2(self.files, self.arc)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v2_list(self):
        names = sorted(e.name for e in bf.list_entries(self.arc))
        self.assertEqual(names, sorted(self.files))

    def test_v2_verify_clean(self):
        self.assertEqual(bf.verify(self.arc), [])

    def test_v2_unpack_round_trip(self):
        dest = os.path.join(self.tmp, "dest")
        n = bf.unpack(self.arc, dest)
        self.assertEqual(n, len(self.files))
        for name, data in self.files.items():
            with open(os.path.join(dest, *name.split("/")), "rb") as fh:
                self.assertEqual(fh.read(), data)


class TestV3Compression(unittest.TestCase):
    """v3 (solid LZMA) must beat v1 (per-file zlib) on redundant data."""

    def setUp(self):
        self.tmp = os.path.abspath("v2comp_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        chunk = ("the quick brown fox jumps over the lazy dog. " * 40 + "\n").encode()
        for i in range(40):
            with open(os.path.join(self.src, "file_%02d.txt" % i), "wb") as fh:
                fh.write(chunk)
                fh.write(("file number %d\n" % i).encode() * 50)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v2_smaller_than_v1_on_redundant_data(self):
        files = {}
        for dirpath, _dirs, fns in os.walk(self.src):
            for fn in fns:
                full = os.path.join(dirpath, fn)
                with open(full, "rb") as fh:
                    files[os.path.relpath(full, self.src).replace(os.sep, "/")] = fh.read()
        v1arc = os.path.join(self.tmp, "v1.bry")
        pack_v1(files, v1arc)
        v3arc = os.path.join(self.tmp, "v3.bry")
        bf.pack([self.src], v3arc, level=6)
        v1size = os.path.getsize(v1arc)
        v3size = os.path.getsize(v3arc)
        self.assertLess(v3size, v1size,
                        "v3 (%d) should beat v1 (%d) on redundant data" % (v3size, v1size))


class TestPassword(unittest.TestCase):
    """Password protection (AES-256-GCM). Skipped if 'cryptography' is missing."""

    def setUp(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography package not installed")
        self.tmp = os.path.abspath("pw_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "secret.txt"), "w") as fh:
            fh.write("top secret\n" * 100)
        self.arc = os.path.join(self.tmp, "enc.bry")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_round_trip_with_password(self):
        bf.pack([self.src], self.arc, password="s3cr3t!")
        self.assertEqual(bf.verify(self.arc, password="s3cr3t!"), [])
        dest = os.path.join(self.tmp, "dest")
        n = bf.unpack(self.arc, dest, password="s3cr3t!")
        self.assertEqual(n, 2)  # dir + file
        with open(os.path.join(dest, "src", "secret.txt")) as fh:
            self.assertEqual(fh.read(), "top secret\n" * 100)

    def test_list_needs_password(self):
        bf.pack([self.src], self.arc, password="s3cr3t!")
        with self.assertRaises(bf.BryError):
            bf.list_entries(self.arc)

    def test_wrong_password_fails(self):
        bf.pack([self.src], self.arc, password="s3cr3t!")
        problems = bf.verify(self.arc, password="wrong")
        self.assertEqual(len(problems), 1)
        self.assertIn("wrong password", problems[0])
        with self.assertRaises(bf.CorruptArchive):
            bf.unpack(self.arc, os.path.join(self.tmp, "d"), password="wrong")

    def test_filenames_are_encrypted(self):
        bf.pack([self.src], self.arc, password="s3cr3t!")
        with open(self.arc, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"secret.txt", raw)

    def test_empty_password_rejected(self):
        with self.assertRaises(bf.BryError):
            bf.pack([self.src], self.arc, password="")

    def test_cli_pack_with_env_password(self):
        env = dict(os.environ, BRY_PASSWORD="env-secret")
        import subprocess, sys
        projroot = os.path.dirname(os.path.dirname(os.path.abspath(bf.__file__)))
        r = subprocess.run(
            [sys.executable, "-m", "bry.cli", "pack", self.src,
             "-o", self.arc, "--password"],
            capture_output=True, text=True, env=env, cwd=projroot)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[encrypted]", r.stdout)
        r = subprocess.run(
            [sys.executable, "-m", "bry.cli", "verify", self.arc,
             "--password"],
            capture_output=True, text=True, env=env, cwd=projroot)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestIncompressible(unittest.TestCase):
    """Already-compressed files are stored as-is, honestly reported."""

    def setUp(self):
        self.tmp = os.path.abspath("inc_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        import random
        rng = random.Random(42)
        with open(os.path.join(self.src, "photo.jpg"), "wb") as fh:
            fh.write(bytes(rng.randrange(256) for _ in range(30000)))
        with open(os.path.join(self.src, "notes.txt"), "w") as fh:
            fh.write("compressible text\n" * 2000)
        with open(os.path.join(self.src, "random.dat"), "wb") as fh:
            fh.write(bytes(rng.randrange(256) for _ in range(30000)))
        self.arc = os.path.join(self.tmp, "out.bry")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_incompressible_files_stored(self):
        count, n_stored = bf.pack([self.src], self.arc)
        self.assertEqual(n_stored, 2)  # photo.jpg + random.dat
        entries = {e.name.split("/")[-1]: e for e in bf.list_entries(self.arc)}
        self.assertTrue(entries["photo.jpg"].stored)
        self.assertTrue(entries["random.dat"].stored)
        self.assertFalse(entries["notes.txt"].stored)

    def test_stored_files_round_trip(self):
        bf.pack([self.src], self.arc)
        self.assertEqual(bf.verify(self.arc), [])
        dest = os.path.join(self.tmp, "dest")
        bf.unpack(self.arc, dest)
        base = os.path.basename(self.src)
        for fn in ("photo.jpg", "notes.txt", "random.dat"):
            with open(os.path.join(self.src, fn), "rb") as a, \
                 open(os.path.join(dest, base, fn), "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_stored_beats_lzma_on_random_data(self):
        # packing must be fast: random data must NOT go through LZMA
        import time
        t0 = time.time()
        bf.pack([self.src], self.arc, level=9)
        self.assertLess(time.time() - t0, 10, "incompressible data slowed packing")


class TestRecovery(unittest.TestCase):
    """Recovery records: damage it, repair it, verify it."""

    def setUp(self):
        self.tmp = os.path.abspath("rec_tmp_%s" % self._testMethodName)
        os.makedirs(self.tmp, exist_ok=True)
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        # >128 KiB body so we span multiple 64 KiB shards
        with open(os.path.join(self.src, "big.txt"), "w") as fh:
            fh.write("recovery test line\n" * 12000)
        self.arc = os.path.join(self.tmp, "out.bry")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _damage_body_byte(self):
        with open(self.arc, "rb") as fh:
            raw = fh.read()
        rec = bf._recovery_info(raw)
        pos = rec["orig_len"] // 2  # guaranteed inside the archive body
        raw = bytearray(raw)
        raw[pos] ^= 0xFF
        with open(self.arc, "wb") as fh:
            fh.write(bytes(raw))

    def _damage_parity_byte(self):
        with open(self.arc, "rb") as fh:
            raw = fh.read()
        rec = bf._recovery_info(raw)
        raw = bytearray(raw)
        raw[rec["orig_len"]] ^= 0xFF  # first byte of the parity region
        with open(self.arc, "wb") as fh:
            fh.write(bytes(raw))

    def test_repair_round_trip(self):
        bf.pack([self.src], self.arc, recovery=10)
        self.assertEqual(bf.verify(self.arc), [])
        self._damage_body_byte()
        problems = bf.verify(self.arc)
        self.assertEqual(len(problems), 1)
        self.assertIn("repair with", problems[0])
        n = bf.repair(self.arc)
        self.assertEqual(n, 1)
        self.assertEqual(bf.verify(self.arc), [])
        dest = os.path.join(self.tmp, "dest")
        bf.unpack(self.arc, dest)
        base = os.path.basename(self.src)
        with open(os.path.join(self.src, "big.txt"), "rb") as a, \
             open(os.path.join(dest, base, "big.txt"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_damaged_parity_reported(self):
        bf.pack([self.src], self.arc, recovery=10)
        self._damage_parity_byte()
        problems = bf.verify(self.arc)
        self.assertEqual(len(problems), 1)
        self.assertIn("recovery data is damaged", problems[0])
        with self.assertRaises(bf.BryError):
            bf.repair(self.arc)

    def test_repair_clean_archive_is_noop(self):
        bf.pack([self.src], self.arc, recovery=10)
        self.assertEqual(bf.repair(self.arc), 0)

    def test_repair_without_recovery_fails(self):
        bf.pack([self.src], self.arc)
        with self.assertRaises(bf.BryError):
            bf.repair(self.arc)

    def test_recovery_footer_ignored_by_readers(self):
        # readers must strip recovery bytes, not choke on them
        bf.pack([self.src], self.arc, recovery=10)
        entries = bf.list_entries(self.arc)
        self.assertTrue(any(e.name.endswith("big.txt") for e in entries))


class TestUpdateCheck(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._orig_cache = cli._update_cache_file
        self._orig_version = cli.__version__
        cli._update_cache_file = lambda: os.path.join(self.tmp, "update.json")
        cli.__version__ = "2.1.0"

    def tearDown(self):
        cli._update_cache_file = self._orig_cache
        cli.__version__ = self._orig_version
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_check(self):
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            cli._maybe_check_update()
        return buf.getvalue()

    def test_ver_tuple(self):
        self.assertGreater(cli._ver_tuple("v2.2.0"), cli._ver_tuple("2.1.0"))
        self.assertEqual(cli._ver_tuple("2.1.0"), cli._ver_tuple("v2.1.0"))

    def test_newer_version_reported_from_cache(self):
        import json, time
        with open(os.path.join(self.tmp, "update.json"), "w") as fh:
            json.dump({"checked": time.time(), "latest": "v9.9.9"}, fh)
        out = self._run_check()
        self.assertIn("9.9.9", out)

    def test_current_version_silent(self):
        import json, time
        with open(os.path.join(self.tmp, "update.json"), "w") as fh:
            json.dump({"checked": time.time(), "latest": "v2.1.0"}, fh)
        self.assertEqual(self._run_check(), "")

    def test_network_failure_is_silent(self):
        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("down"))
        try:
            self.assertEqual(self._run_check(), "")
        finally:
            urllib.request.urlopen = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)

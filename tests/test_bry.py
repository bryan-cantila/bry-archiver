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


def _v2_index_end(path):
    """Return the file offset where the v2 solid compressed stream starts."""
    with open(path, "rb") as fh:
        raw = fh.read()
    assert raw[:4] == b"BRY\x02", "expected a v2 archive"
    count = struct.unpack(">I", raw[6:10])[0]
    off = 10  # magic(4) + flags(1) + method(1) + file_count(4)
    for _ in range(count):
        name_len = struct.unpack(">H", raw[off:off + 2])[0]
        off += 30 + name_len  # entry meta (30) + name
    return raw, off


def corrupt_stream_byte(path):
    """Flip one byte inside the v2 solid compressed stream."""
    raw, stream_off = _v2_index_end(path)
    raw = bytearray(raw)
    # stay clear of the 13-byte LZMA ALONE header; hit the coded data
    pos = stream_off + 13 + (len(raw) - stream_off - 13) // 2
    raw[pos] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


def corrupt_crc_byte(path):
    """Flip one byte of the first *file* entry's stored CRC32 (v2 index)."""
    raw, _stream_off = _v2_index_end(path)
    raw = bytearray(raw)
    count = struct.unpack(">I", raw[6:10])[0]
    off = 10
    for _ in range(count):
        name_len = struct.unpack(">H", raw[off:off + 2])[0]
        name = raw[off + 30:off + 30 + name_len].decode("utf-8")
        if not name.endswith("/"):  # first real file entry
            crc_off = off + 2 + 8 + 8  # name_len + orig_size + offset
            raw[crc_off] ^= 0xFF
            break
        off += 30 + name_len
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


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
            self.assertEqual(fh.read(4), b"BRY\x02")

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
        a1 = os.path.join(self.tmp, "a1.bry")
        a9 = os.path.join(self.tmp, "a9.bry")
        bf.pack([self.src], a1, level=1)
        bf.pack([self.src], a9, level=9)
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
        self.assertIn("solid data stream", problems[0])

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


class TestV2Compression(unittest.TestCase):
    """v2 (solid LZMA) must beat v1 (per-file zlib) on redundant data."""

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
        v2arc = os.path.join(self.tmp, "v2.bry")
        bf.pack([self.src], v2arc, level=6)
        v1size = os.path.getsize(v1arc)
        v2size = os.path.getsize(v2arc)
        self.assertLess(v2size, v1size,
                        "v2 (%d) should beat v1 (%d) on redundant data" % (v2size, v1size))


if __name__ == "__main__":
    unittest.main(verbosity=2)

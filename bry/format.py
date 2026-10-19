"""Reader and writer for the .bry archive format (v2).

v2 layout (all multi-byte integers big-endian):

    header:      magic(4) flags(1) method(1) file_count(4)
    per entry:   name_len(2) name(name_len) orig_size(8) offset(8)
                 crc32(4) mtime(8)
    stream:      lzma-compressed (FORMAT_ALONE) concatenation of every
                 non-directory file's bytes, in entry order

magic is b"BRY\\x02". method 1 = LZMA. flags is reserved (0).
Directories are entries whose name ends in "/" (orig_size == 0, no payload).
crc32 is computed over the original (uncompressed) file bytes.
offset is the byte offset of the file's data inside the DECOMPRESSED stream.

v2 is "solid": all files share one compression stream, so redundancy
*across* files is exploited too (this is the main trick RAR/7z use to
beat ZIP, which compresses every file independently).

v1 archives (magic b"BRY\\x01", per-file zlib payloads) remain readable.
"""

import lzma
import os
import struct
import zlib
from dataclasses import dataclass

MAGIC_V1 = b"BRY\x01"
MAGIC = b"BRY\x02"
VERSION = 2

METHOD_LZMA = 1

_HEADER2 = struct.Struct(">4sBBI")    # magic, flags, method, file_count
_ENTRY2 = struct.Struct(">HQQIQ")     # name_len, orig_size, offset, crc32, mtime

# --- v1 layout (read-only legacy support) ---
_HEADER_V1 = struct.Struct(">4sBI")   # magic, flags, file_count
_ENTRY_V1 = struct.Struct(">HQQIq")   # name_len, orig_size, comp_size, crc32, mtime


class BryError(Exception):
    """Base error for .bry archive problems."""


class NotABryArchive(BryError):
    """Raised when a file does not carry the .bry magic bytes."""


class CorruptArchive(BryError):
    """Raised when an archive fails structural or integrity checks."""


@dataclass
class Entry:
    name: str
    size: int          # original size in bytes
    comp_size: int     # compressed size in bytes (0 for v2: solid stream)
    crc32: int
    mtime: int
    is_dir: bool


def _iter_inputs(paths):
    """Yield (arcname, realpath) pairs in deterministic order."""
    for path in paths:
        path = os.path.abspath(path)
        base = os.path.basename(path.rstrip(os.sep)) or path
        if os.path.isdir(path):
            yield base + "/", path
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, os.path.dirname(path))
                    yield rel.replace(os.sep, "/"), full
                for name in sorted(dirs):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, os.path.dirname(path))
                    yield rel.replace(os.sep, "/") + "/", full
        elif os.path.isfile(path):
            yield base, path
        else:
            raise BryError("no such file or directory: %s" % path)


def pack(paths, out, level=6):
    """Create a .bry archive (v2, solid LZMA) at *out* containing *paths*.

    level is the LZMA preset (1-9); higher compresses more but is slower
    and hungrier for memory. Returns the entry count.
    """
    if not 1 <= level <= 9:
        raise BryError("compression level must be 1-9, got %r" % (level,))
    items = list(_iter_inputs(paths))
    metas = []  # (arcname, data or None, crc32, mtime, offset)
    solid = bytearray()
    for arcname, realpath in items:
        mtime = int(os.stat(realpath).st_mtime)
        if arcname.endswith("/"):
            metas.append((arcname, None, 0, mtime, 0))
        else:
            with open(realpath, "rb") as src:
                data = src.read()
            crc = zlib.crc32(data) & 0xFFFFFFFF
            metas.append((arcname, data, crc, mtime, len(solid)))
            solid += data
    comp = lzma.compress(bytes(solid), preset=level, format=lzma.FORMAT_ALONE)
    with open(out, "wb") as fh:
        fh.write(_HEADER2.pack(MAGIC, 0, METHOD_LZMA, len(metas)))
        for arcname, data, crc, mtime, offset in metas:
            name = arcname.encode("utf-8")
            size = 0 if data is None else len(data)
            fh.write(_ENTRY2.pack(len(name), size, offset, crc, mtime))
            fh.write(name)
        fh.write(comp)
    return len(metas)


def _read_exact(fh, n, what):
    buf = fh.read(n)
    if len(buf) != n:
        raise CorruptArchive("truncated archive while reading %s" % what)
    return buf


def _magic_of(archive):
    with open(archive, "rb") as fh:
        magic = fh.read(4)
    if magic == MAGIC:
        return 2
    if magic == MAGIC_V1:
        return 1
    raise NotABryArchive("not a .bry archive (bad magic bytes)")


def _safe_join(dest, name):
    if name.startswith("/") or ".." in name.split("/"):
        raise CorruptArchive("unsafe entry name %r" % name)
    target = os.path.join(dest, *name.split("/"))
    if os.path.commonpath([os.path.abspath(dest)]) != os.path.commonpath(
        [os.path.abspath(dest), os.path.abspath(target)]
    ):
        raise CorruptArchive("entry escapes destination: %r" % name)
    return target


# ---------------------------------------------------------------- v2 reader

def _read_entry_meta_v2(fh):
    raw = _read_exact(fh, _ENTRY2.size, "entry header")
    name_len, orig_size, offset, crc32, mtime = _ENTRY2.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, offset, crc32, mtime


def _read_index_v2(archive):
    """Return (entries, comp_stream_bytes)."""
    with open(archive, "rb") as fh:
        raw = _read_exact(fh, _HEADER2.size, "header")
        _magic, _flags, method, count = _HEADER2.unpack(raw)
        if method != METHOD_LZMA:
            raise CorruptArchive("unsupported compression method %r" % (method,))
        index = [_read_entry_meta_v2(fh) for _ in range(count)]
        comp = fh.read()
    return index, comp


def _decompress_v2(comp):
    try:
        return lzma.decompress(comp)
    except lzma.LZMAError as exc:
        raise CorruptArchive("solid data stream is corrupt: %s" % exc)


def _entries_v2(archive):
    """Read and fully verify a v2 archive. Returns [(Entry, bytes|None)]."""
    index, comp = _read_index_v2(archive)
    solid = _decompress_v2(comp)
    out = []
    for name, orig_size, offset, crc32, mtime in index:
        is_dir = name.endswith("/")
        data = None
        if not is_dir:
            data = solid[offset:offset + orig_size]
            if len(data) != orig_size:
                raise CorruptArchive(
                    "size mismatch in %r: expected %d bytes, got %d"
                    % (name, orig_size, len(data))
                )
            if (zlib.crc32(data) & 0xFFFFFFFF) != crc32:
                raise CorruptArchive(
                    "CRC mismatch in %r: archive is corrupt" % name
                )
        out.append((Entry(name, orig_size, 0, crc32, mtime, is_dir), data))
    return out


def _list_entries_v2(archive):
    index, _comp = _read_index_v2(archive)
    return [
        Entry(name, orig_size, 0, crc32, mtime, name.endswith("/"))
        for name, orig_size, _offset, crc32, mtime in index
    ]


# ---------------------------------------------------------------- v1 reader (legacy)

def _read_entry_meta_v1(fh):
    raw = _read_exact(fh, _ENTRY_V1.size, "entry header")
    name_len, orig_size, comp_size, crc32, mtime = _ENTRY_V1.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, comp_size, crc32, mtime


def _entries_v1(archive):
    """Read entries with payload; verify CRCs. Returns [(Entry, bytes|None)]."""
    out = []
    with open(archive, "rb") as fh:
        raw = _read_exact(fh, _HEADER_V1.size, "header")
        _magic, _flags, count = _HEADER_V1.unpack(raw)
        for _ in range(count):
            name, orig_size, comp_size, crc32, mtime = _read_entry_meta_v1(fh)
            is_dir = name.endswith("/")
            data = None
            if not is_dir:
                comp = _read_exact(fh, comp_size, "data for %r" % name)
                try:
                    data = zlib.decompress(comp)
                except zlib.error as exc:
                    raise CorruptArchive("cannot decompress %r: %s" % (name, exc))
                if len(data) != orig_size:
                    raise CorruptArchive(
                        "size mismatch in %r: expected %d bytes, got %d"
                        % (name, orig_size, len(data))
                    )
                if (zlib.crc32(data) & 0xFFFFFFFF) != crc32:
                    raise CorruptArchive(
                        "CRC mismatch in %r: archive is corrupt" % name
                    )
            out.append((Entry(name, orig_size, comp_size, crc32, mtime, is_dir), data))
    return out


def _list_entries_v1(archive):
    entries = []
    with open(archive, "rb") as fh:
        raw = _read_exact(fh, _HEADER_V1.size, "header")
        _magic, _flags, count = _HEADER_V1.unpack(raw)
        for _ in range(count):
            name, orig_size, comp_size, crc32, mtime = _read_entry_meta_v1(fh)
            is_dir = name.endswith("/")
            if not is_dir and comp_size:
                fh.seek(comp_size, os.SEEK_CUR)
            entries.append(Entry(name, orig_size, comp_size, crc32, mtime, is_dir))
    return entries


# ---------------------------------------------------------------- public API (version-dispatched)

def list_entries(archive):
    """Return [Entry, ...] without decompressing payload data."""
    if _magic_of(archive) == 2:
        return _list_entries_v2(archive)
    return _list_entries_v1(archive)


def verify(archive):
    """Check archive integrity. Returns a list of problem strings (empty = OK)."""
    try:
        if _magic_of(archive) == 2:
            _entries_v2(archive)
        else:
            _entries_v1(archive)
    except BryError as exc:
        return [str(exc)]
    return []


def unpack(archive, dest="."):
    """Extract *archive* into *dest*. Returns the entry count."""
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    if _magic_of(archive) == 2:
        entries = _entries_v2(archive)
    else:
        entries = _entries_v1(archive)
    for entry, data in entries:
        target = _safe_join(dest, entry.name)
        if entry.is_dir:
            os.makedirs(target, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
        try:
            os.utime(target, (entry.mtime, entry.mtime))
        except OSError:
            pass
    return len(entries)

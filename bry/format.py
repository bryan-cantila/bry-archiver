"""Reader and writer for the .bry archive format (v1).

Format (all multi-byte integers big-endian):

    header:      magic(4) flags(1) file_count(4)
    per entry:   name_len(2) name(name_len) orig_size(8) comp_size(8)
                 crc32(4) mtime(8) comp_data(comp_size)

magic is b"BRY\\x01". flags is reserved (0). Directories are entries whose
name ends in "/" with orig_size == comp_size == 0 and no comp_data.
crc32 is computed over the original (uncompressed) file bytes.
"""

import os
import struct
import zlib
from dataclasses import dataclass

MAGIC = b"BRY\x01"
VERSION = 1

_HEADER = struct.Struct(">4sBI")      # magic, flags, file_count
_ENTRY = struct.Struct(">HQQIq")      # name_len, orig_size, comp_size, crc32, mtime


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
    comp_size: int     # compressed size in bytes
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
    """Create a .bry archive at *out* containing *paths*.

    level is the zlib compression level (1-9). Returns the entry count.
    """
    if not 1 <= level <= 9:
        raise BryError("compression level must be 1-9, got %r" % (level,))
    items = list(_iter_inputs(paths))
    with open(out, "wb") as fh:
        fh.write(_HEADER.pack(MAGIC, 0, len(items)))
        for arcname, realpath in items:
            name = arcname.encode("utf-8")
            mtime = int(os.stat(realpath).st_mtime)
            if arcname.endswith("/"):
                fh.write(_ENTRY.pack(len(name), 0, 0, 0, mtime))
                fh.write(name)
            else:
                with open(realpath, "rb") as src:
                    data = src.read()
                crc = zlib.crc32(data) & 0xFFFFFFFF
                comp = zlib.compress(data, level)
                fh.write(_ENTRY.pack(len(name), len(data), len(comp), crc, mtime))
                fh.write(name)
                fh.write(comp)
    return len(items)


def _read_exact(fh, n, what):
    buf = fh.read(n)
    if len(buf) != n:
        raise CorruptArchive("truncated archive while reading %s" % what)
    return buf


def _read_header(fh):
    raw = _read_exact(fh, _HEADER.size, "header")
    magic, _flags, count = _HEADER.unpack(raw)
    if magic != MAGIC:
        raise NotABryArchive("not a .bry archive (bad magic bytes)")
    return count


def _read_entry_meta(fh):
    raw = _read_exact(fh, _ENTRY.size, "entry header")
    name_len, orig_size, comp_size, crc32, mtime = _ENTRY.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, comp_size, crc32, mtime


def _safe_join(dest, name):
    if name.startswith("/") or ".." in name.split("/"):
        raise CorruptArchive("unsafe entry name %r" % name)
    target = os.path.join(dest, *name.split("/"))
    if os.path.commonpath([os.path.abspath(dest)]) != os.path.commonpath(
        [os.path.abspath(dest), os.path.abspath(target)]
    ):
        raise CorruptArchive("entry escapes destination: %r" % name)
    return target


def list_entries(archive):
    """Return [Entry, ...] without decompressing payload data."""
    entries = []
    with open(archive, "rb") as fh:
        count = _read_header(fh)
        for _ in range(count):
            name, orig_size, comp_size, crc32, mtime = _read_entry_meta(fh)
            is_dir = name.endswith("/")
            if not is_dir and comp_size:
                fh.seek(comp_size, os.SEEK_CUR)
            entries.append(Entry(name, orig_size, comp_size, crc32, mtime, is_dir))
    return entries


def _read_all_entries(archive):
    """Read entries with payload; verify CRCs. Returns [(Entry, bytes|None)]."""
    out = []
    with open(archive, "rb") as fh:
        count = _read_header(fh)
        for _ in range(count):
            name, orig_size, comp_size, crc32, mtime = _read_entry_meta(fh)
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


def verify(archive):
    """Check archive integrity. Returns a list of problem strings (empty = OK)."""
    try:
        _read_all_entries(archive)
    except BryError as exc:
        return [str(exc)]
    return []


def unpack(archive, dest="."):
    """Extract *archive* into *dest*. Returns the entry count."""
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    entries = _read_all_entries(archive)
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

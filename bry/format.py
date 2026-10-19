"""Reader and writer for the .bry archive format (v3).

v3 layout (all multi-byte integers big-endian):

    header:      magic(4) flags(1) method(1) file_count(4)
    per entry:   name_len(2) name(name_len) orig_size(8) offset(8)
                 crc32(4) mtime(8) stored(1)
    comp_len:    8 bytes — length of the compressed stream that follows
    comp_stream: lzma-compressed (FORMAT_ALONE) concatenation of every
                 *compressible* file's bytes, in entry order
    raw_stream:  raw concatenation of every *stored* (incompressible)
                 file's bytes, in entry order

magic is b"BRY\\x02" for v2, b"BRY\\x03" for v3 (see below).
method 1 = LZMA, method 2 = LZMA + AES-256-GCM (password).
stored=1 means the file's bytes live in raw_stream (offset is relative
to raw_stream); stored=0 means comp_stream (offset relative to the
DECOMPRESSED comp_stream). Incompressible files (photos, video, zips…)
are stored as-is: faster to pack, and the tool reports them honestly.

v1 (BRY\\x01, per-file zlib) and v2 (BRY\\x02, solid LZMA, no stored byte,
no comp_len field) remain readable.

Optional recovery records (Reed-Solomon-style XOR parity, see below) may
be appended after the archive body; readers strip them before parsing.
"""

import hashlib
import io
import lzma
import os
import struct
import zlib
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - optional dependency
    _HAS_CRYPTO = False

MAGIC_V1 = b"BRY\x01"
MAGIC_V2 = b"BRY\x02"
MAGIC = b"BRY\x03"
FORMAT_VERSION = 3

METHOD_LZMA = 1
METHOD_LZMA_AESGCM = 2  # password-protected: index + streams encrypted

_KDF_ITERS = 600_000  # OWASP recommendation for PBKDF2-HMAC-SHA256
_AAD = MAGIC + bytes([METHOD_LZMA_AESGCM])  # bound to header by GCM

_HEADER = struct.Struct(">4sBBI")       # magic, flags, method, file_count
_HEADER2E = struct.Struct(">4sBB16s12s")  # magic, flags, method, salt, nonce
_ENTRY = struct.Struct(">HQQIQB")       # name_len, orig_size, offset, crc32, mtime, stored
_ENTRY_V2 = struct.Struct(">HQQIQ")     # v2 layout (no stored byte)
_ENTRY_V1 = struct.Struct(">HQQIq")     # v1 layout

# --- recovery records ---
_REC_MAGIC = b"BRYR"
_REC_META = struct.Struct(">4sIIIQI")  # magic, shard, n_data, n_parity, orig_len, parity_crc
_REC_SHARD = 65536  # 64 KiB


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
    comp_size: int     # compressed size in bytes (0 for solid formats)
    crc32: int
    mtime: int
    is_dir: bool
    stored: bool = False  # True: kept as-is (incompressible), not compressed


# Extensions that are (almost) always already compressed.
_INCOMPRESSIBLE_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".mp3", ".ogg", ".oga", ".flac", ".m4a", ".opus",
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".lz4",
    ".cab", ".iso", ".dmg", ".woff", ".woff2",
}


def _looks_incompressible(name, data):
    """Heuristic: True if compressing this file is a waste of time."""
    if not data:
        return False
    if os.path.splitext(name)[1].lower() in _INCOMPRESSIBLE_EXTS:
        return True
    sample = data[:65536]
    return len(zlib.compress(sample, 1)) / len(sample) > 0.92


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


def _require_crypto():
    if not _HAS_CRYPTO:
        raise BryError(
            "password protection needs the 'cryptography' package: "
            "pip install cryptography"
        )


def _derive_key(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _KDF_ITERS)


def pack(paths, out, level=6, password=None, recovery=0):
    """Create a .bry archive (v3) at *out* containing *paths*.

    level is the LZMA preset (1-9). If *password* is given, the index and
    both streams are encrypted with AES-256-GCM (needs 'cryptography').
    *recovery* is a percent (1-50) of Reed-Solomon-style parity appended
    so damaged archives can be repaired with :func:`repair`.
    Returns (entry_count, stored_count).
    """
    if not 1 <= level <= 9:
        raise BryError("compression level must be 1-9, got %r" % (level,))
    if password is not None:
        _require_crypto()
        if not password:
            raise BryError("password cannot be empty")
    if not 0 <= recovery <= 50:
        raise BryError("recovery must be 0-50, got %r" % (recovery,))
    items = list(_iter_inputs(paths))
    metas = []  # (arcname, data or None, crc32, mtime, offset, stored)
    comp_solid = bytearray()
    raw_solid = bytearray()
    n_stored = 0
    for arcname, realpath in items:
        mtime = int(os.stat(realpath).st_mtime)
        if arcname.endswith("/"):
            metas.append((arcname, None, 0, mtime, 0, False))
            continue
        with open(realpath, "rb") as src:
            data = src.read()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        stored = _looks_incompressible(arcname, data)
        if stored:
            n_stored += 1
            metas.append((arcname, data, crc, mtime, len(raw_solid), True))
            raw_solid += data
        else:
            metas.append((arcname, data, crc, mtime, len(comp_solid), False))
            comp_solid += data
    comp = lzma.compress(bytes(comp_solid), preset=level, format=lzma.FORMAT_ALONE)
    raw = bytes(raw_solid)
    index = io.BytesIO()
    for arcname, _data, crc, mtime, offset, stored in metas:
        name = arcname.encode("utf-8")
        size = 0 if _data is None else len(_data)
        index.write(_ENTRY.pack(len(name), size, offset, crc, mtime, 1 if stored else 0))
        index.write(name)
    body = io.BytesIO()
    if password is None:
        body.write(_HEADER.pack(MAGIC, 0, METHOD_LZMA, len(metas)))
        body.write(index.getvalue())
        body.write(struct.pack(">Q", len(comp)))
        body.write(comp)
        body.write(raw)
    else:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(password, salt)
        plain = (struct.pack(">I", len(metas)) + index.getvalue()
                 + struct.pack(">Q", len(comp)) + comp + raw)
        blob = AESGCM(key).encrypt(nonce, plain, _AAD)
        body.write(_HEADER2E.pack(MAGIC, 0, METHOD_LZMA_AESGCM, salt, nonce))
        body.write(blob)
    with open(out, "wb") as fh:
        fh.write(body.getvalue())
    if recovery:
        _add_recovery(out, recovery)
    return len(metas), n_stored


# ---------------------------------------------------------------- recovery

def _xor_shards(shards):
    x = 0
    for s in shards:
        x ^= int.from_bytes(s, "big")
    return x.to_bytes(len(shards[0]), "big")


def _add_recovery(path, pct):
    """Append XOR-parity recovery records (pct% overhead) to the archive."""
    with open(path, "rb") as fh:
        data = fh.read()
    shard = _REC_SHARD
    n_data = (len(data) + shard - 1) // shard or 1
    n_parity = max(1, round(n_data * pct / 100))
    padded = data + b"\x00" * (n_data * shard - len(data))
    shards = [padded[i * shard:(i + 1) * shard] for i in range(n_data)]
    # data shards split into n_parity groups; one XOR parity per group
    gsize = (n_data + n_parity - 1) // n_parity
    parity = []
    for j in range(n_parity):
        grp = shards[j * gsize:(j + 1) * gsize]
        parity.append(_xor_shards(grp) if grp else b"\x00" * shard)
    crcs = b"".join(struct.pack(">I", zlib.crc32(s) & 0xFFFFFFFF) for s in shards)
    parity_bytes = b"".join(parity)
    with open(path, "ab") as fh:
        fh.write(parity_bytes)
        fh.write(crcs)
        fh.write(_REC_META.pack(_REC_MAGIC, shard, n_data, n_parity, len(data),
                                zlib.crc32(parity_bytes) & 0xFFFFFFFF))


def _recovery_info(raw):
    """Parse the recovery footer of *raw* bytes; None if absent/invalid."""
    if len(raw) < _REC_META.size or raw[-_REC_META.size:-_REC_META.size + 4] != _REC_MAGIC:
        return None
    _m, shard, n_data, n_parity, orig_len, parity_crc = _REC_META.unpack(
        raw[-_REC_META.size:])
    if not (0 < shard <= 1 << 20 and n_data > 0 and n_parity > 0 and orig_len > 0):
        return None
    rec_len = n_parity * shard + n_data * 4 + _REC_META.size
    if orig_len + rec_len != len(raw):
        return None
    crcs_off = orig_len + n_parity * shard
    crcs = struct.unpack(">%dI" % n_data, raw[crcs_off:crcs_off + n_data * 4])
    parity_ok = (zlib.crc32(raw[orig_len:crcs_off]) & 0xFFFFFFFF) == parity_crc
    return {"shard": shard, "n_data": n_data, "n_parity": n_parity,
            "orig_len": orig_len, "crcs": crcs, "parity_ok": parity_ok}


def _body_and_recovery(archive):
    """Return (archive_body_bytes, recovery_info|None)."""
    with open(archive, "rb") as fh:
        raw = fh.read()
    rec = _recovery_info(raw)
    if rec is None:
        return raw, None
    return raw[:rec["orig_len"]], rec


def _bad_shards(body, rec):
    shard, n_data = rec["shard"], rec["n_data"]
    padded = body + b"\x00" * (n_data * shard - len(body))
    bad = []
    for i in range(n_data):
        s = padded[i * shard:(i + 1) * shard]
        if (zlib.crc32(s) & 0xFFFFFFFF) != rec["crcs"][i]:
            bad.append(i)
    return bad


def repair(archive):
    """Repair a damaged archive using its recovery records.

    Returns the number of repaired 64 KiB blocks. Raises BryError if the
    archive has no recovery data or is too damaged to repair.
    """
    with open(archive, "rb") as fh:
        raw = fh.read()
    rec = _recovery_info(raw)
    if rec is None:
        raise BryError("no recovery data in this archive (pack with --recovery)")
    shard, n_data, n_parity, orig_len = (rec["shard"], rec["n_data"],
                                         rec["n_parity"], rec["orig_len"])
    body = raw[:orig_len]
    padded = body + b"\x00" * (n_data * shard - len(body))
    shards = [bytearray(padded[i * shard:(i + 1) * shard]) for i in range(n_data)]
    par_off = orig_len
    parity = [raw[par_off + j * shard:par_off + (j + 1) * shard]
              for j in range(n_parity)]
    bad = [i for i in range(n_data)
           if (zlib.crc32(shards[i]) & 0xFFFFFFFF) != rec["crcs"][i]]
    if not bad:
        if not rec["parity_ok"]:
            raise BryError("recovery data itself is damaged; re-pack with --recovery")
        return 0
    if not rec["parity_ok"]:
        raise BryError("recovery data is damaged; cannot repair")
    gsize = (n_data + n_parity - 1) // n_parity
    for j in range(n_parity):
        grp = list(range(j * gsize, min((j + 1) * gsize, n_data)))
        bad_in_grp = [i for i in grp if i in bad]
        if len(bad_in_grp) > 1:
            raise BryError(
                "too damaged to repair (%d bad blocks in one parity group)" % len(bad_in_grp))
        if bad_in_grp:
            i = bad_in_grp[0]
            x = int.from_bytes(parity[j], "big")
            for k in grp:
                if k != i:
                    x ^= int.from_bytes(shards[k], "big")
            shards[i] = bytearray(x.to_bytes(shard, "big"))
            if (zlib.crc32(shards[i]) & 0xFFFFFFFF) != rec["crcs"][i]:
                raise BryError("repair failed integrity check; recovery data is damaged")
    with open(archive, "wb") as fh:
        fh.write(b"".join(shards)[:orig_len])
        fh.write(raw[orig_len:])  # keep the original recovery section
    return len(bad)


# ---------------------------------------------------------------- reading

def _read_exact(fh, n, what):
    buf = fh.read(n)
    if len(buf) != n:
        raise CorruptArchive("truncated archive while reading %s" % what)
    return buf


def _magic_of_buf(buf):
    magic = bytes(buf[:4])
    if magic == MAGIC:
        return 3
    if magic == MAGIC_V2:
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


def _read_entry_meta(fh):
    raw = _read_exact(fh, _ENTRY.size, "entry header")
    name_len, orig_size, offset, crc32, mtime, stored = _ENTRY.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, offset, crc32, mtime, bool(stored)


def _read_entry_meta_v2(fh):
    raw = _read_exact(fh, _ENTRY_V2.size, "entry header")
    name_len, orig_size, offset, crc32, mtime = _ENTRY_V2.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, offset, crc32, mtime


def _read_entry_meta_v1(fh):
    raw = _read_exact(fh, _ENTRY_V1.size, "entry header")
    name_len, orig_size, comp_size, crc32, mtime = _ENTRY_V1.unpack(raw)
    name = _read_exact(fh, name_len, "entry name").decode("utf-8")
    return name, orig_size, comp_size, crc32, mtime


def _decrypt_body(buf, password):
    """Decrypt a method-2 body; return (index, comp, raw_stream) tuples."""
    _require_crypto()
    if password is None:
        raise BryError("archive is encrypted: use --password")
    fh = io.BytesIO(buf)
    raw = _read_exact(fh, _HEADER2E.size, "header")
    _magic, _flags, _method, salt, nonce = _HEADER2E.unpack(raw)
    blob = fh.read()
    key = _derive_key(password, salt)
    try:
        plain = AESGCM(key).decrypt(nonce, blob, _AAD)
    except InvalidTag:
        raise CorruptArchive("wrong password or archive is corrupt")
    fh = io.BytesIO(plain)
    count = struct.unpack(">I", _read_exact(fh, 4, "entry count"))[0]
    index = [_read_entry_meta(fh) for _ in range(count)]
    comp_len = struct.unpack(">Q", _read_exact(fh, 8, "stream length"))[0]
    comp = _read_exact(fh, comp_len, "compressed stream")
    return index, comp, fh.read()


def _read_body_v3(buf):
    fh = io.BytesIO(buf)
    raw = _read_exact(fh, _HEADER.size, "header")
    _magic, _flags, method, count = _HEADER.unpack(raw)
    if method not in (METHOD_LZMA, METHOD_LZMA_AESGCM):
        raise CorruptArchive("unsupported compression method %r" % (method,))
    index = [_read_entry_meta(fh) for _ in range(count)]
    comp_len = struct.unpack(">Q", _read_exact(fh, 8, "stream length"))[0]
    comp = _read_exact(fh, comp_len, "compressed stream")
    return index, comp, fh.read()


def _decompress_stream(comp):
    try:
        return lzma.decompress(comp)
    except lzma.LZMAError as exc:
        raise CorruptArchive("compressed data stream is corrupt: %s" % exc)


def _entries_v3(buf, password=None):
    method = buf[5]  # magic(4) flags(1) method(1) ...
    if method == METHOD_LZMA_AESGCM:
        index, comp, raw_stream = _decrypt_body(buf, password)
    else:
        index, comp, raw_stream = _read_body_v3(buf)
    solid = _decompress_stream(comp)
    out = []
    for name, orig_size, offset, crc32, mtime, stored in index:
        is_dir = name.endswith("/")
        data = None
        if not is_dir:
            src = raw_stream if stored else solid
            data = src[offset:offset + orig_size]
            if len(data) != orig_size:
                raise CorruptArchive(
                    "size mismatch in %r: expected %d bytes, got %d"
                    % (name, orig_size, len(data)))
            if (zlib.crc32(data) & 0xFFFFFFFF) != crc32:
                raise CorruptArchive("CRC mismatch in %r: archive is corrupt" % name)
        out.append((Entry(name, orig_size, 0, crc32, mtime, is_dir, stored), data))
    return out


def _list_entries_v3(buf, password=None):
    method = buf[5]  # magic(4) flags(1) method(1) ...
    if method == METHOD_LZMA_AESGCM:
        index, _comp, _raw = _decrypt_body(buf, password)
    else:
        fh = io.BytesIO(buf)
        raw = _read_exact(fh, _HEADER.size, "header")
        _magic, _flags, _m, count = _HEADER.unpack(raw)
        index = [_read_entry_meta(fh) for _ in range(count)]
    return [Entry(n, s, 0, c, m, n.endswith("/"), st)
            for n, s, _o, c, m, st in index]


def _entries_v2(fh):
    """v2 reader (legacy): solid LZMA, no stored byte, no comp_len field."""
    raw = _read_exact(fh, _HEADER.size, "header")
    _magic, _flags, method, count = _HEADER.unpack(raw)
    if method != METHOD_LZMA:
        raise CorruptArchive("unsupported compression method %r" % (method,))
    index = [_read_entry_meta_v2(fh) for _ in range(count)]
    comp = fh.read()
    solid = _decompress_stream(comp)
    out = []
    for name, orig_size, offset, crc32, mtime in index:
        is_dir = name.endswith("/")
        data = None
        if not is_dir:
            data = solid[offset:offset + orig_size]
            if len(data) != orig_size:
                raise CorruptArchive("size mismatch in %r" % name)
            if (zlib.crc32(data) & 0xFFFFFFFF) != crc32:
                raise CorruptArchive("CRC mismatch in %r: archive is corrupt" % name)
        out.append((Entry(name, orig_size, 0, crc32, mtime, is_dir), data))
    return out


def _list_entries_v2(fh):
    raw = _read_exact(fh, _HEADER.size, "header")
    _magic, _flags, _method, count = _HEADER.unpack(raw)
    index = [_read_entry_meta_v2(fh) for _ in range(count)]
    return [Entry(n, s, 0, c, m, n.endswith("/"))
            for n, s, _o, c, m in index]


_HEADER_V1 = struct.Struct(">4sBI")    # v1: magic, flags, file_count (9 bytes)


def _entries_v1(fh):
    """v1 reader (legacy): per-file zlib payloads."""
    raw = _read_exact(fh, _HEADER_V1.size, "header")
    _magic, _flags, count = _HEADER_V1.unpack(raw)
    out = []
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
                raise CorruptArchive("size mismatch in %r" % name)
            if (zlib.crc32(data) & 0xFFFFFFFF) != crc32:
                raise CorruptArchive("CRC mismatch in %r: archive is corrupt" % name)
        out.append((Entry(name, orig_size, comp_size, crc32, mtime, is_dir), data))
    return out


def _list_entries_v1(fh):
    raw = _read_exact(fh, _HEADER_V1.size, "header")
    _magic, _flags, count = _HEADER_V1.unpack(raw)
    entries = []
    for _ in range(count):
        name, orig_size, comp_size, crc32, mtime = _read_entry_meta_v1(fh)
        is_dir = name.endswith("/")
        if not is_dir and comp_size:
            fh.seek(comp_size, os.SEEK_CUR)
        entries.append(Entry(name, orig_size, comp_size, crc32, mtime, is_dir))
    return entries


# ---------------------------------------------------------------- public API

def _open_body(archive):
    body, _rec = _body_and_recovery(archive)
    return io.BytesIO(body)


def list_entries(archive, password=None):
    """Return [Entry, ...] without decompressing payload data."""
    buf = _open_body(archive).getvalue()
    v = _magic_of_buf(buf)
    if v == 3:
        return _list_entries_v3(buf, password)
    fh = io.BytesIO(buf)
    if v == 2:
        return _list_entries_v2(fh)
    return _list_entries_v1(fh)


def verify(archive, password=None):
    """Check archive integrity. Returns a list of problem strings (empty = OK)."""
    try:
        with open(archive, "rb") as fh:
            raw = fh.read()
        rec = _recovery_info(raw)
        body = raw[:rec["orig_len"]] if rec else raw
        if rec:
            if not rec["parity_ok"]:
                return ["recovery data is damaged; re-pack with --recovery "
                        "to restore protection"]
            bad = _bad_shards(body, rec)
            if bad:
                return ["%d damaged 64 KiB block(s); repair with: bry repair %s"
                        % (len(bad), archive)]
        buf = body
        v = _magic_of_buf(buf)
        if v == 3:
            _entries_v3(buf, password)
        else:
            fh = io.BytesIO(buf)
            if v == 2:
                _entries_v2(fh)
            else:
                _entries_v1(fh)
    except BryError as exc:
        return [str(exc)]
    return []


def unpack(archive, dest=".", password=None):
    """Extract *archive* into *dest*. Returns the entry count."""
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    body, rec = _body_and_recovery(archive)
    v = _magic_of_buf(body)
    try:
        if v == 3:
            entries = _entries_v3(body, password)
        else:
            fh = io.BytesIO(body)
            entries = _entries_v2(fh) if v == 2 else _entries_v1(fh)
    except CorruptArchive as exc:
        if rec and _bad_shards(body, rec):
            raise CorruptArchive(
                "%s [recovery data present — try: bry repair %s]" % (exc, archive))
        raise
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

# .bry archive format — version 3

This document specifies the `.bry` binary format precisely so independent
implementations can read and write it. All multi-byte integers are
**big-endian**. Strings are **UTF-8**.

Version 3 is a **solid** archive: every compressible file's bytes are
concatenated into one stream and compressed together with LZMA, so
redundancy *across* files is exploited too (the main technique RAR and
7-Zip use to beat ZIP, which compresses each file independently).
Files that are already compressed (photos, video, zips…) are detected
and stored as-is in a separate raw stream — faster to pack, and the
tool reports them honestly. Versions 1 and 2 remain readable — see the
appendices.

## File layout

```
+-------------------------------+
| header                        |
+-------------------------------+
| entry 0: meta + name          |
+-------------------------------+
| entry 1: meta + name          |
+-------------------------------+
| ...                           |
+-------------------------------+
| comp_len (8 bytes)            |
+-------------------------------+
| compressed data stream        |
+-------------------------------+
| raw data stream (stored files)|
+-------------------------------+
| recovery records (optional)   |
+-------------------------------+
```

The index comes first so `list` never needs to touch the data streams.

## Header (10 bytes)

| Field      | Size | Type   | Value                                        |
|------------|------|--------|----------------------------------------------|
| magic      | 4    | bytes  | `42 52 59 03` — ASCII "BRY" + `0x03`         |
| flags      | 1    | uint8  | reserved, must be `0`                        |
| method     | 1    | uint8  | `1` = LZMA; `2` = LZMA + AES-256-GCM (password) |
| file_count | 4    | uint32 | number of index entries that follow          |

## Index entry (variable length)

| Field     | Size        | Type   | Notes                                              |
|-----------|-------------|--------|----------------------------------------------------|
| name_len  | 2           | uint16 | length of `name` in bytes                          |
| name      | `name_len`  | bytes  | UTF-8 path, `/` as separator                       |
| orig_size | 8           | uint64 | uncompressed size in bytes                         |
| offset    | 8           | uint64 | byte offset inside the entry's stream (see `stored`) |
| crc32     | 4           | uint32 | CRC-32 (IEEE) of the **original** file bytes       |
| mtime     | 8           | int64  | modification time, seconds since Unix epoch        |
| stored    | 1           | uint8  | `1` = incompressible, kept as-is in the raw stream |

## Data streams

`comp_len` (8 bytes, uint64) gives the length of the compressed stream.

- **Compressed stream:** `lzma.compress()` of the concatenation of every
  *compressible* (stored=0) non-directory file's original bytes, in index
  order, using `FORMAT_ALONE` (a self-describing raw LZMA1 stream, no XZ
  container overhead). The CLI maps its `--level` 1–9 directly to the
  LZMA preset.
- **Raw stream:** concatenation of every *stored* (stored=1) file's
  original bytes, in index order, uncompressed.

An entry's `offset` is relative to its own stream: the decompressed
compressed-stream for stored=0, the raw stream for stored=1.

A file is stored as-is when it looks incompressible: its extension is a
known-already-compressed type (`.jpg`, `.mp4`, `.zip`, …), or a 64 KiB
sample compresses to less than 8% smaller with zlib level 1. Directory
entries (`name` ends in `/`) have `orig_size == 0`, `offset == 0`,
`crc32 == 0`, `stored == 0`, and contribute no bytes to either stream.

## Directories

A directory is an entry whose `name` ends in `/`. Reader implementations
must create directories before extracting the files inside them.

## Reader requirements

1. Strip recovery records first (see below): if the file ends with a
   valid `BRYR` footer, the archive body is the first `orig_len` bytes.
2. If the first 4 bytes are not `42 52 59 03`, `42 52 59 02`, or
   `42 52 59 01`, reject the file with a "not a .bry archive" error.
3. If fewer than `file_count` index entries can be read, report the
   archive as truncated.
4. Decompress the stream; on failure, report the archive as corrupt
   (a damaged solid stream cannot attribute the damage to one file —
   same as RAR/7-Zip solid blocks).
5. For each file entry, verify the sliced length equals `orig_size` and
   its CRC-32 equals `crc32`. On mismatch, report the entry `name`.
6. On extraction, reject entry names that are absolute or contain `..`
   segments — they must not escape the destination directory.
7. Unknown `flags` bits and unknown `method` values: report unsupported
   rather than guessing.

## Password protection (method 2)

`bry pack --password` encrypts the index **and** both data streams, so
file names are hidden too. Layout:

```
header:      magic(4) flags(1) method(1)=0x02 salt(16) nonce(12)
blob:        AES-256-GCM( salt-derived key, nonce ) over:
                 file_count(4) + index entries + comp_len(8)
                 + compressed stream + raw stream
```

- Key: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output.
- Salt (16 bytes) and nonce (12 bytes) are random per archive (`os.urandom`).
- Associated data bound into the GCM tag: `42 52 59 03 02` (magic + method).
- A wrong password fails GCM authentication — readers must report
  "wrong password or archive is corrupt", never silently wrong data.
- Requires the `cryptography` package; the rest of bry stays dependency-free.

## Recovery records (optional)

`bry pack --recovery N` (N = 1–50) appends N% of parity data so a
damaged archive can be repaired with `bry repair`. The archive body is
split into 64 KiB shards; data shards are divided into groups and each
group gets one XOR parity shard (repairs any single damaged shard per
group — the realistic bit-rot / bad-sector case). Every data shard is
covered by a CRC-32 so damage is located precisely.

```
+--------------------------------+
| archive body (see above)       |
+--------------------------------+
| parity shards (n_parity x 64K) |
+--------------------------------+
| shard CRCs (n_data x 4 bytes)  |
+--------------------------------+
| footer (28 bytes)              |
+--------------------------------+
```

Footer (28 bytes): magic `42 52 59 52` ("BRYR"), shard_size(4, uint32),
n_data(4, uint32), n_parity(4, uint32), orig_len(8, uint64),
parity_crc(4, uint32 — CRC-32 of the parity region).

Readers detect the footer by its magic in the last 28 bytes and must
validate `orig_len + parity + crcs + 28 == file size` before trusting it
(a body that merely ends in "BRYR" by coincidence must not be misread).

Repair rule: per parity group, zero bad shards → nothing to do; exactly
one bad shard → reconstruct via XOR and re-check its CRC; more than one
→ report "too damaged to repair". If the parity region itself is
damaged (parity_crc mismatch), repair must refuse rather than guess.

---

## Appendix: version 2 (legacy, read-only)

magic `42 52 59 02`. Same 10-byte header; entries are 30 bytes
(`>HQQIQ`, no `stored` byte); a single solid LZMA stream follows the
index with no `comp_len` field (it runs to end of body).

## Appendix: version 1 (legacy, read-only)

Writers no longer produce v1, but readers must still accept it.

```
header:      magic(4) flags(1) file_count(4)
per entry:   name_len(2) name(name_len) orig_size(8) comp_size(8)
             crc32(4) mtime(8) comp_data(comp_size)
```

magic is `42 52 59 01`. Each entry carries its own zlib-compressed
(RFC 1950) payload, compressed independently at level 1–9.

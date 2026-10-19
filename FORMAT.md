# .bry archive format — version 2

This document specifies the `.bry` binary format precisely so independent
implementations can read and write it. All multi-byte integers are
**big-endian**. Strings are **UTF-8**.

Version 2 is a **solid** archive: every file's bytes are concatenated into
one stream and compressed together with LZMA, so redundancy *across*
files is exploited too (the main technique RAR and 7-Zip use to beat ZIP,
which compresses each file independently). Version 1 archives remain
readable — see the appendix.

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
| solid compressed data stream  |
+-------------------------------+
```

The index comes first so `list` never needs to touch the data stream.

## Header (10 bytes)

| Field      | Size | Type   | Value                                        |
|------------|------|--------|----------------------------------------------|
| magic      | 4    | bytes  | `42 52 59 02` — ASCII "BRY" + `0x02`         |
| flags      | 1    | uint8  | reserved, must be `0`                        |
| method     | 1    | uint8  | `1` = LZMA (raw LZMA1 stream, `FORMAT_ALONE`) |
| file_count | 4    | uint32 | number of index entries that follow          |

## Index entry (variable length)

| Field     | Size        | Type   | Notes                                              |
|-----------|-------------|--------|----------------------------------------------------|
| name_len  | 2           | uint16 | length of `name` in bytes                          |
| name      | `name_len`  | bytes  | UTF-8 path, `/` as separator                       |
| orig_size | 8           | uint64 | uncompressed size in bytes                         |
| offset    | 8           | uint64 | byte offset of this file inside the *decompressed* stream |
| crc32     | 4           | uint32 | CRC-32 (IEEE) of the **original** file bytes       |
| mtime     | 8           | int64  | modification time, seconds since Unix epoch        |

## Data stream

`lzma.compress()` of the concatenation of every non-directory file's
original bytes, in index order, using `FORMAT_ALONE` (a self-describing
raw LZMA1 stream, no XZ container overhead). The CLI maps its `--level`
1–9 directly to the LZMA preset.

## Directories

A directory is an entry whose `name` ends in `/`. Directory entries have
`orig_size == 0`, `offset == 0`, `crc32 == 0`, and contribute no bytes to
the stream. Reader implementations must create directories before
extracting the files inside them.

## Reader requirements

1. If the first 4 bytes are neither `42 52 59 02` nor `42 52 59 01`,
   reject the file with a "not a .bry archive" error.
2. If fewer than `file_count` index entries can be read, report the
   archive as truncated.
3. Decompress the stream; on failure, report the archive as corrupt
   (a damaged solid stream cannot attribute the damage to one file —
   same as RAR/7-Zip solid blocks).
4. For each file entry, verify the sliced length equals `orig_size` and
   its CRC-32 equals `crc32`. On mismatch, report the entry `name`.
5. On extraction, reject entry names that are absolute or contain `..`
   segments — they must not escape the destination directory.
6. Unknown `flags` bits and unknown `method` values: report unsupported
   rather than guessing.

---

## Appendix: version 1 (legacy, read-only)

Writers no longer produce v1, but readers must still accept it.

```
header:      magic(4) flags(1) file_count(4)
per entry:   name_len(2) name(name_len) orig_size(8) comp_size(8)
             crc32(4) mtime(8) comp_data(comp_size)
```

magic is `42 52 59 01`. Each entry carries its own zlib-compressed
(RFC 1950) payload, compressed independently at level 1–9.

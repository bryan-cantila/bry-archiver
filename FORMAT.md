# .bry archive format — version 1

This document specifies the `.bry` binary format precisely so independent
implementations can read and write it. All multi-byte integers are
**big-endian**. Strings are **UTF-8**.

## File layout

```
+-------------------------------+
| header                        |
+-------------------------------+
| entry 0: meta + name + data   |
+-------------------------------+
| entry 1: meta + name + data   |
+-------------------------------+
| ...                           |
+-------------------------------+
```

## Header (9 bytes)

| Field      | Size | Type   | Value                                  |
|------------|------|--------|----------------------------------------|
| magic      | 4    | bytes  | `42 52 59 01` — ASCII "BRY" + `0x01`   |
| flags      | 1    | uint8  | reserved, must be `0`                  |
| file_count | 4    | uint32 | number of entries that follow          |

## Entry (variable length)

| Field     | Size        | Type   | Notes                                              |
|-----------|-------------|--------|----------------------------------------------------|
| name_len  | 2           | uint16 | length of `name` in bytes                          |
| name      | `name_len`  | bytes  | UTF-8 path, `/` as separator                       |
| orig_size | 8           | uint64 | uncompressed size in bytes                         |
| comp_size | 8           | uint64 | compressed size in bytes                           |
| crc32     | 4           | uint32 | CRC-32 (IEEE) of the **original** file bytes       |
| mtime     | 8           | int64  | modification time, seconds since Unix epoch        |
| comp_data | `comp_size` | bytes  | zlib-compressed payload (RFC 1950)                 |

## Directories

A directory is an entry whose `name` ends in `/`. Directory entries have
`orig_size == 0`, `comp_size == 0`, `crc32 == 0`, and no `comp_data`.
Reader implementations must create directories before extracting the
files inside them.

## Reader requirements

1. If the first 4 bytes are not `42 52 59 01`, reject the file with a
   "not a .bry archive" error.
2. If fewer than `file_count` entries can be read, report the archive
   as truncated.
3. After decompressing an entry, verify that the decompressed length
   equals `orig_size` and that its CRC-32 equals `crc32`. On mismatch,
   report the entry `name`.
4. On extraction, reject entry names that are absolute or contain `..`
   segments — they must not escape the destination directory.
5. Unknown `flags` bits must be ignored (forward compatibility).

## Design notes

- CRC-32 is computed over original bytes so corruption is detected even
  if the compressed stream still decompresses.
- zlib was chosen because it is in every Python standard library and
  produces a portable stream any language can decode.
- The format is deliberately simple: no solid compression, no
  encryption, no multi-volume support in v1.

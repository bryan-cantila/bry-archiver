# bry-archiver

![bry-archiver logo](docs/logo.png)

*Created by devuvo*

[![Tests](https://github.com/bryan-cantila/bry-archiver/actions/workflows/tests.yml/badge.svg)](https://github.com/bryan-cantila/bry-archiver/actions)
[![License: devuvo Community](https://img.shields.io/badge/license-devuvo_Community-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Version](https://img.shields.io/badge/version-2.1.0-lightgrey.svg)](pyproject.toml)

A cross-platform command-line compression tool that creates `.bry` archives.

```
$ bry pack photos/ documents/ -o backup.bry --level 9
packed 248 entries -> backup.bry (41.2 MB) [37 stored as-is]

$ bry pack secrets/ -o secrets.bry --password
Password: ********
packed 12 entries -> secrets.bry (8.1 MB) [encrypted]

$ bry pack project/ -o project.bry --recovery 5
packed 312 entries -> project.bry (88.4 MB) [5% recovery]

$ bry list backup.bry
    2.4 MB  photos/img_0042.jpg  [stored]
  812.0 KB  documents/report.pdf
  ...
248 entries, 96.5 MB total

$ bry verify backup.bry
backup.bry: OK

$ bry unpack backup.bry -d restored/
unpacked 248 entries -> /home/user/restored

$ bry repair damaged.bry
damaged.bry: repaired 1 damaged 64 KiB block(s)
```

## Demo

![bry pack, list and verify](docs/demo-pack.png)
![bry help and unpack](docs/demo-help.png)

## Features

- **`.bry` format v3** — a solid archive: all compressible files share one LZMA compression stream, so redundancy *across* files is squeezed out too (the trick RAR/7-Zip use to beat ZIP). Already-compressed files (photos, video, zips) are detected and stored as-is instead of wasting time. Per-file CRC32 integrity checks, documented in [FORMAT.md](FORMAT.md)
- **Password protection** — `bry pack --password` encrypts file contents *and* names with AES-256-GCM (PBKDF2 key derivation); wrong passwords fail cleanly. Needs `pip install cryptography`; everything else stays dependency-free
- **Recovery records** — `bry pack --recovery 5` appends parity data; `bry repair` fixes damaged archives. RAR's best trick, and neither ZIP nor 7z has it
- **Update check** — bry tells you when a new release is on GitHub (checked at most once a day; `--no-update-check` to skip)
- **Backward compatible** — v1 (per-file zlib) and v2 (solid LZMA) archives still list, verify, and unpack fine
- **Cross-platform** — pure Python standard library, runs on Windows, macOS, and Linux with Python 3.9+
- **Five commands** — `pack`, `unpack`, `list`, `verify`, `repair`; nothing else to learn
- **Safe extraction** — entries that try to escape the destination directory are rejected
- **Unicode filenames** — entry names stored as UTF-8
- **Zero dependencies** — nothing to install beyond Python itself (password protection optionally uses the `cryptography` package)

## What's new

- **2.1.0** — Password protection (`--password`, AES-256-GCM, needs `pip install cryptography`); incompressible files auto-stored as-is with honest reporting; recovery records (`--recovery 1-50`, `bry repair`); daily new-release check; format v3
- **2.0.0** — Solid LZMA compression (format v2): ~29% smaller than ZIP on redundant data
- **1.0.0** — Initial release: pack/unpack/list/verify, per-file zlib (format v1)

## Install

```
pip install .
```

or, isolated from your system Python:

```
pipx install .
```

This provides the `bry` command. Requires Python 3.9 or newer.

## Usage

Create an archive from files and/or directories:

```
bry pack <paths...> -o archive.bry [--level 1-9] [--password] [--recovery 1-50]
```

Extract, list, verify, or repair:

```
bry unpack archive.bry [-d destination/]
bry list archive.bry
bry verify archive.bry
bry repair archive.bry
```

`verify` checks integrity without writing anything to disk: when recovery
data is present it first checks the 64 KiB blocks (reporting damage as
repairable), then decompresses every entry in memory and checks its CRC32.
Any mismatch reports the offending filename and exits non-zero.

## Format

`.bry` is a documented binary format — see [FORMAT.md](FORMAT.md) for the exact field layout. v3 uses a solid LZMA stream plus a raw stream for incompressible files; readers reject files without a valid `BRY` magic, and any CRC or size mismatch names the corrupt file.

## Development notes

Original format and implementation, designed for this project. Built with an AI-assisted workflow: format spec and CLI behavior defined up front, implementation reviewed against the spec, full test suite green before release.

## License

**Free to use — just credit devuvo.** Personal, educational, and non-commercial use is free, provided you give visible credit (e.g. "Created by devuvo" with a link to https://www.devuvo.com). Business or income-generating use requires devuvo's prior approval — contact admin@devuvo.com (a license fee may apply). See [LICENSE](LICENSE) for the full terms.

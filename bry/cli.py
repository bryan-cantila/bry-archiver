"""Command-line interface for bry-archiver."""

import argparse
import os
import sys

from . import __version__
from .format import BryError, list_entries, pack, unpack, verify


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def cmd_pack(args):
    try:
        count = pack(args.paths, args.output, level=args.level)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    size = os.path.getsize(args.output)
    print("packed %d entr%s -> %s (%s)" % (
        count, "y" if count == 1 else "ies", args.output, _human(size)))
    return 0


def cmd_unpack(args):
    try:
        count = unpack(args.archive, args.dest)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    print("unpacked %d entr%s -> %s" % (
        count, "y" if count == 1 else "ies", os.path.abspath(args.dest)))
    return 0


def cmd_list(args):
    try:
        entries = list_entries(args.archive)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    total = sum(e.size for e in entries if not e.is_dir)
    for e in entries:
        shown = e.name if e.name.endswith("/") else e.name + ("/" if e.is_dir else "")
        print("%10s  %s" % (_human(e.size), shown))
    print("%d entries, %s total" % (len(entries), _human(total)))
    return 0


def cmd_verify(args):
    try:
        problems = verify(args.archive)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    if problems:
        for p in problems:
            print("bry: corrupt: %s" % p, file=sys.stderr)
        return 1
    print("%s: OK" % args.archive)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="bry",
        description="bry-archiver %s: pack and unpack .bry archives" % __version__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    pp = sub.add_parser("pack", help="create a .bry archive")
    pp.add_argument("paths", nargs="+", help="files/directories to archive")
    pp.add_argument("-o", "--output", required=True, help="output .bry file")
    pp.add_argument("--level", type=int, default=6, choices=range(1, 10),
                    metavar="1-9",
                    help="compression level 1-9 (default 6; higher is smaller but slower)")
    pp.set_defaults(func=cmd_pack)

    up = sub.add_parser("unpack", help="extract a .bry archive")
    up.add_argument("archive", help=".bry file to extract")
    up.add_argument("-d", "--dest", default=".", help="destination directory")
    up.set_defaults(func=cmd_unpack)

    lp = sub.add_parser("list", help="list archive contents")
    lp.add_argument("archive", help=".bry file to list")
    lp.set_defaults(func=cmd_list)

    vp = sub.add_parser("verify", help="verify archive integrity")
    vp.add_argument("archive", help=".bry file to verify")
    vp.set_defaults(func=cmd_verify)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

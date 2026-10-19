"""Command-line interface for bry-archiver."""

import argparse
import json
import os
import sys
import time
import urllib.request

from . import __version__
from .format import BryError, list_entries, pack, repair, unpack, verify

_UPDATE_URL = "https://github.com/bryan-cantila/bry-archiver"
_UPDATE_API = "https://api.github.com/repos/bryan-cantila/bry-archiver/releases/latest"


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def _resolve_password(args):
    """Return the password string, or None if --password was not given."""
    if not args.password:
        return None
    env = os.environ.get("BRY_PASSWORD")
    if env:
        return env
    import getpass
    try:
        pw = getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return None
    if not pw:
        print("bry: error: password cannot be empty", file=sys.stderr)
        sys.exit(1)
    return pw


def _add_password_arg(p):
    p.add_argument("--password", action="store_true",
                   help="password-protect / unlock the archive "
                        "(prompts securely; needs 'pip install cryptography')")


def cmd_pack(args):
    password = _resolve_password(args)
    if args.password and password is None:
        return 1
    try:
        count, n_stored = pack(args.paths, args.output, level=args.level,
                               password=password, recovery=args.recovery)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    size = os.path.getsize(args.output)
    tags = ""
    if password:
        tags += " [encrypted]"
    if n_stored:
        tags += " [%d stored as-is]" % n_stored
    if args.recovery:
        tags += " [%d%% recovery]" % args.recovery
    print("packed %d entr%s -> %s (%s)%s" % (
        count, "y" if count == 1 else "ies", args.output, _human(size), tags))
    return 0


def cmd_unpack(args):
    password = _resolve_password(args)
    if args.password and password is None:
        return 1
    try:
        count = unpack(args.archive, args.dest, password=password)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    print("unpacked %d entr%s -> %s" % (
        count, "y" if count == 1 else "ies", os.path.abspath(args.dest)))
    return 0


def cmd_list(args):
    password = _resolve_password(args)
    if args.password and password is None:
        return 1
    try:
        entries = list_entries(args.archive, password=password)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    total = sum(e.size for e in entries if not e.is_dir)
    for e in entries:
        shown = e.name if e.name.endswith("/") else e.name + ("/" if e.is_dir else "")
        if e.stored:
            shown += "  [stored]"
        print("%10s  %s" % (_human(e.size), shown))
    print("%d entries, %s total" % (len(entries), _human(total)))
    return 0


def cmd_verify(args):
    password = _resolve_password(args)
    if args.password and password is None:
        return 1
    try:
        problems = verify(args.archive, password=password)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    if problems:
        for p in problems:
            print("bry: corrupt: %s" % p, file=sys.stderr)
        return 1
    print("%s: OK" % args.archive)
    return 0


def cmd_repair(args):
    try:
        n = repair(args.archive)
    except BryError as exc:
        print("bry: error: %s" % exc, file=sys.stderr)
        return 1
    if n:
        print("%s: repaired %d damaged 64 KiB block(s)" % (args.archive, n))
    else:
        print("%s: no damage found, nothing to repair" % args.archive)
    return 0


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v).lstrip("v").split("."))
    except ValueError:
        return ()


def _update_cache_file():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "bry")
    else:
        d = os.path.join(os.path.expanduser("~"), ".cache", "bry")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "update.json")


def _maybe_check_update():
    """Tell the user about a newer GitHub release (at most once a day).

    Never breaks or slows the real command: cached, 5s timeout, all
    errors swallowed.
    """
    try:
        cache = _update_cache_file()
        try:
            with open(cache) as fh:
                state = json.load(fh)
        except (OSError, ValueError):
            state = {}
        now = time.time()
        if now - state.get("checked", 0) < 86400 and "latest" in state:
            latest = state["latest"]
        else:
            req = urllib.request.Request(
                _UPDATE_API, headers={"User-Agent": "bry-archiver"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                latest = json.load(resp)["tag_name"]
            with open(cache, "w") as fh:
                json.dump({"checked": now, "latest": latest}, fh)
        if _ver_tuple(latest) > _ver_tuple(__version__):
            print("bry: version %s is available (you have %s): %s/releases"
                  % (latest, __version__, _UPDATE_URL), file=sys.stderr)
    except Exception:
        pass


def build_parser():
    p = argparse.ArgumentParser(
        prog="bry",
        description="bry-archiver %s: pack and unpack .bry archives" % __version__,
    )
    p.add_argument("--no-update-check", action="store_true",
                   help="skip the daily new-release check")
    sub = p.add_subparsers(dest="command", required=True)

    pp = sub.add_parser("pack", help="create a .bry archive")
    pp.add_argument("paths", nargs="+", help="files/directories to archive")
    pp.add_argument("-o", "--output", required=True, help="output .bry file")
    pp.add_argument("--level", type=int, default=6, choices=range(1, 10),
                    metavar="1-9",
                    help="compression level 1-9 (default 6; higher is smaller but slower)")
    pp.add_argument("--recovery", type=int, default=0, metavar="1-50",
                    help="append 1-50%% recovery data so damaged archives "
                         "can be repaired with 'bry repair'")
    _add_password_arg(pp)
    pp.set_defaults(func=cmd_pack)

    up = sub.add_parser("unpack", help="extract a .bry archive")
    up.add_argument("archive", help=".bry file to extract")
    up.add_argument("-d", "--dest", default=".", help="destination directory")
    _add_password_arg(up)
    up.set_defaults(func=cmd_unpack)

    lp = sub.add_parser("list", help="list archive contents")
    lp.add_argument("archive", help=".bry file to list")
    _add_password_arg(lp)
    lp.set_defaults(func=cmd_list)

    vp = sub.add_parser("verify", help="verify archive integrity")
    vp.add_argument("archive", help=".bry file to verify")
    _add_password_arg(vp)
    vp.set_defaults(func=cmd_verify)

    rp = sub.add_parser("repair", help="repair a damaged archive using its recovery data")
    rp.add_argument("archive", help=".bry file to repair")
    rp.set_defaults(func=cmd_repair)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.no_update_check and not os.environ.get("BRY_NO_UPDATE_CHECK"):
        _maybe_check_update()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

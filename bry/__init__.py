"""bry-archiver: a cross-platform CLI compression tool producing .bry archives."""

__version__ = "2.1.0"

from .format import (
    BryError,
    CorruptArchive,
    Entry,
    NotABryArchive,
    list_entries,
    pack,
    repair,
    unpack,
    verify,
)

__all__ = [
    "BryError",
    "CorruptArchive",
    "Entry",
    "NotABryArchive",
    "list_entries",
    "pack",
    "repair",
    "unpack",
    "verify",
    "__version__",
]

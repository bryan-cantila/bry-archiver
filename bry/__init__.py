"""bry-archiver: a cross-platform CLI compression tool producing .bry archives."""

__version__ = "2.0.0"

from .format import (
    BryError,
    CorruptArchive,
    Entry,
    NotABryArchive,
    list_entries,
    pack,
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
    "unpack",
    "verify",
    "__version__",
]

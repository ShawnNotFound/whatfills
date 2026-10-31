"""whatfills: find out why a disk is full."""

try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("whatfills")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.1.0.dev0"
except ImportError:  # pragma: no cover
    __version__ = "0.1.0.dev0"

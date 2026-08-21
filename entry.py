"""PyInstaller entry point — imports the package properly so relative
imports inside chambua work when frozen."""

from chambua.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

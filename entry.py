"""PyInstaller entry point — imports the package properly so relative
imports inside mail_workbench work when frozen."""

from mail_workbench.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

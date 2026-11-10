"""Operational CLI: python -m app.cli <command>"""
from __future__ import annotations

import sys

import pyotp
from sqlalchemy import select

from .config import get_settings
from .db import create_all, session_scope
from .models import User
from .seed import seed_defaults, seed_demo


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "help"
    s = get_settings()
    if cmd == "init-db":
        if s.environment == "production":
            print("use `alembic upgrade head` in production")
            return 1
        create_all()
        with session_scope() as db:
            seed_defaults(db)
        print("database initialised")
        return 0
    if cmd == "seed-demo":
        create_all()
        with session_scope() as db:
            secrets = seed_demo(db)
        print("Demo users (password: Demo-Passw0rd!) and TOTP secrets:")
        for e, sec in secrets.items():
            print(f"  {e:22s} {sec}")
        return 0
    if cmd == "totp" and len(argv) > 2:
        if s.environment == "production" or s.auth_mode != "dev":
            print("disabled outside dev mode")
            return 1
        with session_scope() as db:
            u = db.execute(select(User).where(User.email == argv[2])).scalar_one_or_none()
            if u is None or not u.totp_secret:
                print("no such dev user")
                return 1
            print(pyotp.TOTP(u.totp_secret).now())
        return 0
    print("commands: init-db | seed-demo | totp <email>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

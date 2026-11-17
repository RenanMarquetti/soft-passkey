"""soft-passkey command line.

  soft-passkey register --origin URL --options FILE|- --out FILE   create a credential; prints the registration response
  soft-passkey sign     --origin URL --options FILE|- [--key FILE] sign an authentication challenge; prints the response
  soft-passkey info     [--key FILE]                               show RP ID and credential id (never the key)

The key is read from --key or from the SOFT_PASSKEY environment variable.
Options are the JSON the RP returns (publicKey or the bare object, base64url fields).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import DEFAULT_ENV, SoftPasskey


def _read_json(path: str) -> dict:
    return json.load(sys.stdin if path == "-" else open(path))


def _load(key_path: str | None) -> SoftPasskey:
    if key_path:
        return SoftPasskey.load(open(key_path).read())
    return SoftPasskey.from_env(DEFAULT_ENV)


def _write_secret(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soft-passkey", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register")
    r.add_argument("--origin", required=True)
    r.add_argument("--options", required=True)
    r.add_argument("--out", required=True, help="file for the exported key (created with mode 600, never overwritten)")
    r.add_argument("--counter", action="store_true", help="increment the signature counter (needs the key file to be rewritten)")
    s = sub.add_parser("sign")
    s.add_argument("--origin", required=True)
    s.add_argument("--options", required=True)
    s.add_argument("--key")
    i = sub.add_parser("info")
    i.add_argument("--key")
    a = p.parse_args(argv)
    if a.cmd == "register":
        passkey, response = SoftPasskey.create(_read_json(a.options), a.origin, counter_increments=a.counter)
        _write_secret(a.out, passkey.export())
        print(json.dumps(response))
    elif a.cmd == "sign":
        passkey = _load(a.key)
        print(json.dumps(passkey.get(_read_json(a.options), a.origin)))
        if a.key and passkey.counter_increments:
            open(a.key, "w").write(passkey.export() + "\n")
    else:
        print(repr(_load(a.key)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

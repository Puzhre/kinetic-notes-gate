#!/usr/bin/env python3
"""Decrypt source/*.enc.json with password from SOURCE_PASSWORD or prompt."""
import argparse, base64, getpass, json, os, sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("need: pip install cryptography")

def decrypt(path: Path, password: str, outdir: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=base64.b64decode(payload["salt"]), iterations=payload["iter"],
    ).derive(password.encode())
    pt = AESGCM(key).decrypt(
        base64.b64decode(payload["iv"]),
        base64.b64decode(payload["ct"]),
        None,
    )
    name = payload.get("name") or path.name.replace(".enc.json", "")
    out = outdir / name
    out.write_bytes(pt)
    print("wrote", out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="*.enc.json paths (default: source/*.enc.json)")
    ap.add_argument("-o", "--outdir", default=".", help="output directory")
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = [Path(f) for f in args.files] or sorted((root / "source").glob("*.enc.json"))
    if not files:
        sys.exit("no .enc.json found")
    pw = os.environ.get("SOURCE_PASSWORD") or getpass.getpass("password: ")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    for f in files:
        decrypt(f, pw, outdir)

if __name__ == "__main__":
    main()

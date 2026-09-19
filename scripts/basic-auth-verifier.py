#!/usr/bin/env python3
"""Read a password from stdin and emit a salted scrypt verifier."""
import hashlib
import secrets
import sys

password = sys.stdin.buffer.read(65537)
if not password or len(password) > 65536:
    sys.exit('Basic password must contain between 1 and 65536 bytes')
salt = secrets.token_bytes(16)
digest = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=32)
print('scrypt-v1:' + salt.hex() + ':' + digest.hex())

#!/usr/bin/env python3
"""Write Ed25519 key material for the Envoy rewrite smoke (host-side only)."""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main() -> int:
    expected_arguments = 2
    if len(sys.argv) != expected_arguments:
        return 2
    runtime = Path(sys.argv[1])
    runtime.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    (runtime / "payment_private.der").write_bytes(private_key.private_bytes_raw())
    (runtime / "payment_public.der").write_bytes(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

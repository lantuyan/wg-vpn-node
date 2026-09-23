"""Request-signing primitives shared by central (auth.py) and the node agent.

PROTOCOL.md §3.2: the canonical string and its HMAC-SHA256. Pure functions,
stdlib only, no app imports -- this module sits at the very bottom of the
import graph so the node agent can sign requests without pulling in any
central module (store, db, ...).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re

#: First line of the canonical string (PROTOCOL.md §3.2). Literal, no version
#: interpolation: a change here is a protocol version bump.
CANONICAL_PREFIX = "WGVPN-HMAC-SHA256"

#: sha256(b"") — the body hash used for requests without a body.
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_RE_B64URL = re.compile(r"\A[A-Za-z0-9_-]+\Z")


def _b64url_decode(text: str) -> bytes:
    """Decode an unpadded (or padded) base64url string to raw bytes.

    ``ValueError`` on anything that is not base64url; never returns partially
    decoded garbage.
    """
    if not isinstance(text, str):
        raise ValueError("install secret must be a string")
    cleaned = text.strip().rstrip("=")
    if not cleaned or not _RE_B64URL.match(cleaned):
        raise ValueError("install secret is not valid base64url")
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
        raise ValueError("install secret is not valid base64url") from exc


def canonical_string(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_sha256: str,
) -> str:
    """PROTOCOL.md §3.2, byte for byte.

    Six literal lines joined with a single ``\\n`` and **no** trailing
    newline: the prefix, the uppercase method, the path (no query string),
    the timestamp exactly as sent, the nonce exactly as sent, and the
    lowercase hex sha256 of the raw body.
    """
    return "\n".join(
        (
            CANONICAL_PREFIX,
            method,
            path,
            timestamp,
            nonce,
            body_sha256,
        )
    )


def body_sha256(body: bytes) -> str:
    """Lowercase hex sha256 of the raw request body bytes."""
    if body is None:
        body = b""
    return hashlib.sha256(body).hexdigest()


def sign(install_secret_b64: str, canonical: str) -> str:
    """HMAC-SHA256 of the canonical string, hex, lowercase.

    ``install_secret_b64`` is the base64url **text** as stored/embedded; the
    key material is the 32 **raw** bytes it decodes to. Signing the base64
    text instead of the decoded bytes is the classic bug here and would make
    every TESTVECTORS.md §1 vector fail. Node secrets use the same format.
    """
    key = _b64url_decode(install_secret_b64)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

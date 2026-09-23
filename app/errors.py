"""API error type and the PROTOCOL.md §4 helper factories.

Every helper returns an ``ApiError`` ready to ``raise``; none of them raise
themselves. The FastAPI exception handler (main.py, out of scope here) turns
an ``ApiError`` into the §4 envelope and sets ``Retry-After`` when present.
"""

from __future__ import annotations


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        detail: object | None = None,
        retry_after: int | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail
        self.retry_after = retry_after
        super().__init__(message)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"ApiError(status={self.status!r}, code={self.code!r}, "
            f"message={self.message!r})"
        )


def bad_request(message: str = "bad request", *, detail: object | None = None) -> ApiError:
    return ApiError(400, "bad_request", message, detail=detail)


def unauthorized(message: str = "unauthorized") -> ApiError:
    return ApiError(401, "unauthorized", message)


def peer_revoked(message: str = "this device has been revoked") -> ApiError:
    return ApiError(403, "peer_revoked", message)


def peer_suspended(message: str = "this device is suspended") -> ApiError:
    return ApiError(403, "peer_suspended", message)


def peer_not_found(message: str = "unknown device_id") -> ApiError:
    return ApiError(404, "peer_not_found", message)


def device_limit_reached(message: str = "install key is at max_peers") -> ApiError:
    return ApiError(409, "device_limit_reached", message)


def address_pool_exhausted(message: str = "no free address in the subnet") -> ApiError:
    return ApiError(409, "address_pool_exhausted", message)


def public_key_in_use(
    message: str = "public_key is already in use by another device",
) -> ApiError:
    """The submitted public key belongs to a different peer.

    Distinct from ``bad_request`` on purpose: it is recoverable, and only the
    client can recover it, by generating a fresh keypair and enrolling again.
    A generic 400 gave the client nothing to act on -- which is how a plain
    "I deleted my config directory" turned into an unexplained failure.

    Carries no detail: the offending peer may belong to a different install
    key, and its id is none of this caller's business.
    """
    return ApiError(409, "public_key_in_use", message)


def node_unavailable(message: str = "this location is not available") -> ApiError:
    """Unknown, pending, disabled, revoked or full node on /enroll."""
    return ApiError(409, "node_unavailable", message)


def node_has_peers(message: str = "node still has peers; move or delete them first") -> ApiError:
    return ApiError(409, "node_has_peers", message)


def node_is_local(message: str = "the local node cannot be revoked or deleted") -> ApiError:
    return ApiError(409, "node_is_local", message)


def body_too_large(message: str = "request body too large") -> ApiError:
    return ApiError(413, "body_too_large", message)


def rate_limited(retry_after: int, message: str = "rate limited") -> ApiError:
    return ApiError(429, "rate_limited", message, retry_after=retry_after)


def quota_exceeded(message: str = "quota used up") -> ApiError:
    return ApiError(451, "quota_exceeded", message)


def wg_unavailable(detail: object | None = None, message: str = "wg0 not ready") -> ApiError:
    return ApiError(503, "wg_unavailable", message, detail=detail)


def internal(message: str = "internal error") -> ApiError:
    return ApiError(500, "internal", message)

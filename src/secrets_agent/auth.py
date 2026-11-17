"""Verify the caller's Cognito ID token on every request (spec 001 REQ-01, REQ-02).

kagent's trusted-proxy auth does not check the signature (D-19), so this server does:
signature against the user pool's JWKS, issuer, audience (the kagent client), token_use
and expiry. Nothing here logs or returns the token.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

import httpx
import jwt

JWKS_TTL_S = 3600
LEEWAY_S = 30


class AuthError(Exception):
    """A refusal the user can act on. `reason` is safe to show (no token content)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Identity:
    sub: str
    email: str
    groups: tuple[str, ...]
    token: str = field(repr=False)     # the raw ID token, only for the OpenBao exchange

    def __str__(self) -> str:           # never print the token
        return f"Identity(sub={self.sub!r}, email={self.email!r}, groups={self.groups!r})"


def bearer(headers: Mapping[str, str] | None) -> str:
    """REQ-02: the bearer token from Authorization, or AuthError('missing')."""
    raw = ""
    if headers:
        raw = headers.get("authorization") or headers.get("Authorization") or ""
    scheme, _, value = raw.strip().partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise AuthError("not signed in: the request carries no user token (kagent must "
                        "forward it: RemoteMCPServer tokenPassthrough)")
    return value.strip()


class Verifier:
    def __init__(self, issuer: str, audience: str,
                 fetch_jwks: Callable[[str], dict] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self._fetch = fetch_jwks or _http_jwks
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded_at = 0.0

    def _key(self, kid: str) -> jwt.PyJWK:
        with self._lock:
            stale = self._clock() - self._loaded_at > JWKS_TTL_S
            if stale or kid not in self._keys:          # refresh on rotation
                data = self._fetch(f"{self.issuer}/.well-known/jwks.json")
                self._keys = {k["kid"]: jwt.PyJWK(k) for k in data.get("keys", []) if "kid" in k}
                self._loaded_at = self._clock()
            if kid not in self._keys:
                raise AuthError("token signed by an unknown key")
            return self._keys[kid]

    def verify(self, token: str) -> Identity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthError("malformed token") from None
        if header.get("alg") != "RS256":
            raise AuthError("token not signed with RS256")
        key = self._key(str(header.get("kid", "")))
        try:
            claims = jwt.decode(
                token, key=key.key, algorithms=["RS256"], audience=self.audience,
                issuer=self.issuer, leeway=LEEWAY_S,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token expired: reload the kagent page to refresh it") from None
        except jwt.InvalidAudienceError:
            raise AuthError("token issued for another application (wrong audience)") from None
        except jwt.InvalidIssuerError:
            raise AuthError("token issued by another identity provider (wrong issuer)") from None
        except jwt.InvalidSignatureError:
            raise AuthError("bad token signature") from None
        except jwt.PyJWTError as e:
            raise AuthError(f"invalid token ({type(e).__name__})") from None
        if claims.get("token_use") != "id":
            raise AuthError("not an ID token (token_use must be 'id')")
        groups = claims.get("cognito:groups") or []
        if isinstance(groups, str):
            groups = [groups]
        return Identity(sub=str(claims["sub"]), email=str(claims.get("email", "")),
                        groups=tuple(sorted(str(g) for g in groups)), token=token)


def _http_jwks(url: str) -> dict:
    r = httpx.get(url, timeout=10.0)
    r.raise_for_status()
    return r.json()

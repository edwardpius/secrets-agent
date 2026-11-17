"""OpenBao calls made with the user's own token (spec 001 REQ-03, GUARD-01).

`Session` holds one user's OpenBao token for one MCP request; there is no other token in
this process. Errors never include tokens or response bodies that could echo them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx


class OpenBaoError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"OpenBao {status}: {reason}")
        self.status = status
        self.reason = reason


def _errors(r: httpx.Response) -> str:
    try:
        errs = r.json().get("errors") or []
        return "; ".join(str(e) for e in errs)[:300] or r.reason_phrase
    except ValueError:
        return r.reason_phrase


class Client:
    """Stateless HTTP client; each call takes the token to use."""

    def __init__(self, addr: str, verify: str | bool = True,
                 transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(base_url=addr.rstrip("/"), verify=verify, timeout=10.0,
                                  transport=transport)

    def login(self, mount: str, role: str, jwt_token: str) -> "Session":
        r = self._http.post(f"/v1/auth/{mount}/login", json={"role": role, "jwt": jwt_token})
        if r.status_code != 200:
            raise OpenBaoError(r.status_code, f"login refused: {_errors(r)}")
        auth = r.json()["auth"]
        names = (set(auth.get("policies") or []) | set(auth.get("identity_policies") or [])) - {"default"}
        return Session(self, auth["client_token"], policies=tuple(sorted(names)),
                       entity_id=auth.get("entity_id", ""))

    def request(self, method: str, path: str, token: str, **kw) -> httpx.Response:
        return self._http.request(method, f"/v1/{path.lstrip('/')}",
                                  headers={"X-Vault-Token": token}, **kw)

    def close(self) -> None:
        self._http.close()


@dataclass
class Session:
    client: Client
    token: str = field(repr=False)
    policies: tuple[str, ...] = ()
    entity_id: str = ""

    def capabilities(self, paths: list[str]) -> dict[str, list[str]]:
        r = self.client.request("POST", "sys/capabilities-self", self.token, json={"paths": paths})
        if r.status_code != 200:
            raise OpenBaoError(r.status_code, _errors(r))
        data = r.json()
        data = data.get("data", data)
        return {p: list(data.get(p, [])) for p in paths}

    def read(self, path: str) -> dict | None:
        """GET with the user's token: the JSON body, or None on 404."""
        r = self.client.request("GET", path, self.token)
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise OpenBaoError(r.status_code, _errors(r))
        return r.json()

    def write(self, path: str, body: dict) -> None:
        """POST with the user's token. The body may hold secret values: it is never logged
        and errors carry only OpenBao's error strings."""
        r = self.client.request("POST", path, self.token, json=body)
        if r.status_code not in (200, 204):
            raise OpenBaoError(r.status_code, _errors(r))

    def list(self, path: str) -> list[str]:
        """LIST (GET ?list=true) with the user's token: the keys, or [] on 404."""
        r = self.client.request("GET", path, self.token, params={"list": "true"})
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            raise OpenBaoError(r.status_code, _errors(r))
        return list((r.json().get("data") or {}).get("keys") or [])

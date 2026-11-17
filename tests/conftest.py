"""Offline fixtures: a fake Cognito (RSA key + JWKS) and a fake OpenBao (httpx MockTransport)."""
from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from secrets_agent.auth import Verifier
from secrets_agent.config import Settings
from secrets_agent.openbao import Client
from secrets_agent.server import Service

ISSUER = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_TEST"
CLIENT_ID = "kagent-client"


class FakeCognito:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="k1", alg="RS256", use="sig")
        self.jwks = {"keys": [jwk]}
        self.fetches = 0

    def fetch(self, url: str) -> dict:
        assert url == f"{ISSUER}/.well-known/jwks.json"
        self.fetches += 1
        return self.jwks

    def token(self, sub="u1", email="dev@example.com", groups=("openbao-secrets-writers",),
              aud=CLIENT_ID, iss=ISSUER, token_use="id", exp_in=900, key=None, kid="k1") -> str:
        now = int(time.time())
        claims = {"sub": sub, "email": email, "cognito:groups": list(groups), "aud": aud,
                  "iss": iss, "token_use": token_use, "iat": now, "exp": now + exp_in}
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": kid})


# Which environments each fake group may create in, and whether it may search.
RIGHTS = {
    "openbao-admins": ({"dev", "staging", "prod"}, True),
    "openbao-secrets-writers": ({"dev", "staging"}, True),
    "openbao-secrets-readers": (set(), True),
}


class FakeOpenBao:
    """Logs in a JWT by decoding its groups (signature checked by the Verifier under test)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []   # (method, path, token)
        self.tokens: dict[str, tuple[str, ...]] = {}          # bao token -> groups
        self.data: dict[str, dict] = {}                       # apps path -> latest data
        self.metadata: dict[str, dict] = {}                   # apps path -> custom_metadata
        self.bodies: list[str] = []                           # raw write bodies (for scans)
        self.fail_metadata_write = False

    def _may_write(self, groups, rel: str) -> bool:
        env = rel.rsplit("/", 1)[-1]
        return rel.count("/") == 2 and any(env in RIGHTS.get(g, (set(), False))[0]
                                           for g in groups)

    def _may_read_metadata(self, groups) -> bool:
        return any(RIGHTS.get(g, (set(), False))[1] for g in groups)

    def _apps(self, request, groups) -> httpx.Response:
        """apps/ KV v2 as the D-25 policies allow it."""
        path = request.url.path.removeprefix("/v1/apps/")
        kind, _, rel = path.partition("/")
        if request.method == "GET" and kind == "metadata":
            if not self._may_read_metadata(groups):
                return httpx.Response(403, json={"errors": ["permission denied"]})
            if rel not in self.metadata and rel not in self.data:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(200, json={"data": {
                "custom_metadata": self.metadata.get(rel) or None, "current_version": 1}})
        if request.method == "POST" and kind == "data":
            self.bodies.append(request.content.decode())
            body = json.loads(request.content)
            # Existing path = an update, which no apps/ MCP policy grants.
            if rel in self.data or not self._may_write(groups, rel):
                return httpx.Response(403, json={"errors": ["1 error occurred:\n\t* permission denied\n\n"]})
            if body.get("options", {}).get("cas") != 0:
                return httpx.Response(403, json={"errors": ["permission denied"]})
            self.data[rel] = dict(body["data"])
            return httpx.Response(200, json={"data": {"version": 1}})
        if request.method == "POST" and kind == "metadata":
            self.bodies.append(request.content.decode())
            body = json.loads(request.content)
            if self.fail_metadata_write:
                return httpx.Response(500, json={"errors": ["internal error"]})
            if set(body) != {"custom_metadata"} or not self._may_write(groups, rel):
                return httpx.Response(403, json={"errors": ["permission denied"]})
            self.metadata[rel] = dict(body["custom_metadata"])
            return httpx.Response(204)
        return httpx.Response(403, json={"errors": ["permission denied"]})

    def handler(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("X-Vault-Token")
        path = request.url.path
        self.calls.append((request.method, path, token))
        if path == "/v1/auth/jwt-mcp/login":
            body = json.loads(request.content)
            claims = jwt.decode(body["jwt"], options={"verify_signature": False})
            groups = tuple(claims.get("cognito:groups", []))
            bao_token = f"hvb.{claims['sub']}.{len(self.tokens)}"
            self.tokens[bao_token] = groups
            return httpx.Response(200, json={"auth": {
                "client_token": bao_token, "policies": ["default"],
                "identity_policies": [f"mcp-{g.removeprefix('openbao-')}" for g in groups],
                "entity_id": f"ent-{claims['sub']}"}})
        if token not in self.tokens:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        groups = self.tokens[token]
        if path == "/v1/sys/capabilities-self":
            paths = json.loads(request.content)["paths"]
            out = {}
            for p in paths:
                caps = set()
                for g in groups:
                    envs, search = RIGHTS.get(g, (set(), False))
                    if p.startswith("apps/data/") and p.rsplit("/", 1)[-1] in envs:
                        caps.add("create")
                    if p == "apps/metadata/" and search:
                        caps.add("list")
                out[p] = sorted(caps) or ["deny"]
            return httpx.Response(200, json={"data": out})
        if path.startswith("/v1/apps/"):
            return self._apps(request, groups)
        return httpx.Response(404, json={"errors": []})


@pytest.fixture
def cognito() -> FakeCognito:
    return FakeCognito()


@pytest.fixture
def bao() -> FakeOpenBao:
    return FakeOpenBao()


@pytest.fixture
def settings() -> Settings:
    return Settings(openbao_addr="https://openbao.test:8200", openbao_ca=None,
                    cognito_issuer=ISSUER, cognito_client_id=CLIENT_ID,
                    ui_url="https://openbao.example.com")


@pytest.fixture
def service(settings, cognito, bao) -> Service:
    client = Client(settings.openbao_addr, transport=httpx.MockTransport(bao.handler))
    return Service(settings, Verifier(ISSUER, CLIENT_ID, fetch_jwks=cognito.fetch), client)

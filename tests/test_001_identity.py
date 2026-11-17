"""Spec 001: identity end to end (REQ-01..04, GUARD-01, GUARD-02), offline."""
from __future__ import annotations

import json
import logging

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from secrets_agent.tools import TOOLS


def call(service, token=None, name="whoami", headers=None):
    h = dict(headers or {})
    if token is not None:
        h["authorization"] = f"Bearer {token}"
    return service.call(name, {}, h)


def test_req04_whoami_writer(service, cognito):
    text, err = call(service, cognito.token(groups=("openbao-secrets-writers",)))
    assert not err, text
    out = json.loads(text)
    assert out["email"] == "dev@example.com"
    assert out["groups"] == ["openbao-secrets-writers"]
    assert out["may_create"] == {"dev": True, "staging": True, "prod": False}
    assert out["may_search"] is True
    assert set(out) == {"email", "groups", "openbao_policies", "may_create", "may_search",
                        "secrets_path"}


@pytest.mark.parametrize("groups,create,search", [
    (("openbao-admins",), {"dev": True, "staging": True, "prod": True}, True),
    (("openbao-secrets-readers",), {"dev": False, "staging": False, "prod": False}, True),
    (("openbao-engineers",), {"dev": False, "staging": False, "prod": False}, False),
])
def test_req04_whoami_per_group(service, cognito, groups, create, search):
    out = json.loads(call(service, cognito.token(groups=groups))[0])
    assert out["may_create"] == create and out["may_search"] is search


@pytest.mark.parametrize("kwargs,reason", [
    ({"exp_in": -3600}, "expired"),
    ({"aud": "other-client"}, "wrong audience"),
    ({"iss": "https://evil.example.com"}, "wrong issuer"),
    ({"token_use": "access"}, "not an ID token"),
])
def test_req01_req02_bad_tokens_refused_without_openbao(service, cognito, bao, kwargs, reason):
    text, err = call(service, cognito.token(**kwargs))
    assert err and reason in text
    assert bao.calls == []                      # REQ-02: no OpenBao call


def test_req02_forged_signature(service, cognito, bao):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    text, err = call(service, cognito.token(key=other))
    assert err and "signature" in text and bao.calls == []


def test_req02_unknown_kid_refetches_once_then_refuses(service, cognito, bao):
    text, err = call(service, cognito.token(kid="rotated"))
    assert err and "unknown key" in text and bao.calls == []


def test_req02_missing_header(service, bao):
    text, err = call(service, None)
    assert err and "not signed in" in text and bao.calls == []


def test_req02_non_bearer_scheme(service, cognito, bao):
    text, err = service.call("whoami", {}, {"authorization": "Basic abc"})
    assert err and "not signed in" in text and bao.calls == []


def test_req03_per_request_login_no_cache(service, cognito, bao):
    """Two users interleaved over one shared MCP session: each call logs in with its own token."""
    a = cognito.token(sub="alice", email="a@example.com", groups=("openbao-admins",))
    b = cognito.token(sub="bob", email="b@example.com", groups=("openbao-secrets-readers",))
    outs = [json.loads(call(service, t)[0]) for t in (a, b, a)]
    assert [o["email"] for o in outs] == ["a@example.com", "b@example.com", "a@example.com"]
    assert [o["may_create"]["prod"] for o in outs] == [True, False, True]
    logins = [c for c in bao.calls if c[1] == "/v1/auth/jwt-mcp/login"]
    assert len(logins) == 3
    # every non-login call used the token from the login just before it
    tokens = [c[2] for c in bao.calls if c[1] != "/v1/auth/jwt-mcp/login"]
    assert tokens[0].startswith("hvb.alice") and tokens[1].startswith("hvb.bob")
    assert tokens[2].startswith("hvb.alice") and tokens[2] != tokens[0]


def test_guard01_every_openbao_call_has_a_user_token(service, cognito, bao):
    call(service, cognito.token())
    assert bao.calls
    for method, path, token in bao.calls:
        assert path == "/v1/auth/jwt-mcp/login" or token, (method, path)


def test_guard02_tokens_not_in_output_or_logs(service, cognito, bao, caplog):
    caplog.set_level(logging.DEBUG)
    tok = cognito.token()
    text, _ = call(service, tok)
    issued = list(bao.tokens)
    text_bad, _ = call(service, cognito.token(exp_in=-3600))
    blob = text + text_bad + caplog.text
    assert tok not in blob
    assert not any(t in blob for t in issued)


def test_unknown_tool(service, cognito):
    text, err = call(service, cognito.token(), name="read_secret")
    assert err and "unknown tool" in text


def test_tool_schemas_strict():
    for t in TOOLS:
        assert t["input_schema"].get("additionalProperties") is False


def test_jwks_cached(service, cognito):
    for _ in range(3):
        call(service, cognito.token())
    assert cognito.fetches == 1

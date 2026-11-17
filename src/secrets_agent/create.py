"""create_secret (spec 002): validate, refuse pasted credentials, generate, write as the user.

Order (SA-003): existence check on the metadata, then the data with cas=0 (a true create:
nothing existing can be overwritten), then the custom metadata. Generated values exist only
in the request body sent to OpenBao: never returned, logged or put on a span (GUARD-02).
"""
from __future__ import annotations

import math
import re
import secrets
import string
import uuid
from collections import Counter
from typing import Any

from .auth import Identity
from .config import Settings
from .openbao import OpenBaoError, Session

ENVIRONMENTS = ("dev", "staging", "prod")
PLACEHOLDER = "PENDING-SET-IN-OPENBAO-UI"
SCHEMA = "1"
KINDS = ("password", "hex", "uuid")
MAX_KEYS = 10

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")          # product, service
TEAM_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
JIRA_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-[0-9]{1,6}$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
AWS_RE = re.compile(r"^openbao/[A-Za-z0-9/_+=.@-]{1,500}$")

FIELDS = {"product", "service", "environment", "description", "team", "jira_ticket", "keys",
          "sync_aws", "aws_secret_name"}
KEY_FIELDS = {"name", "source", "kind"}

CREATE_SECRET = {
    "name": "create_secret",
    "description": (
        "Create one secret at apps/<product>/<service>/<environment> as the signed-in user, "
        "with its metadata. Values are never passed in: each key is either generated here "
        "(source 'generate', kind password|hex|uuid) or left as a placeholder to fill in the "
        "OpenBao UI (source 'ui'). Fails if the path already exists. Only call after the user "
        "has confirmed the full request (path, metadata, keys, AWS name)."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["product", "service", "environment", "description", "team",
                     "jira_ticket", "keys", "sync_aws"],
        "properties": {
            "product": {"type": "string", "description": "lowercase, e.g. payments"},
            "service": {"type": "string", "description": "lowercase, e.g. checkout-api"},
            "environment": {"type": "string", "enum": list(ENVIRONMENTS)},
            "description": {"type": "string", "description": "what it is for, 10-300 chars"},
            "team": {"type": "string", "description": "owning team, lowercase, e.g. platform"},
            "jira_ticket": {"type": "string", "description": "e.g. PAY-1234"},
            "keys": {
                "type": "array", "minItems": 1, "maxItems": MAX_KEYS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "source"],
                    "properties": {
                        "name": {"type": "string", "description": "e.g. DB_PASSWORD"},
                        "source": {"type": "string", "enum": ["generate", "ui"]},
                        "kind": {"type": ["string", "null"], "enum": [*KINDS, None],
                                 "description": "for source 'generate'; default password"},
                    },
                },
            },
            "sync_aws": {"type": "boolean",
                         "description": "also sync to AWS Secrets Manager (spec 004)"},
            "aws_secret_name": {
                "type": ["string", "null"],
                "description": "AWS Secrets Manager name if syncing; default "
                               "openbao/<product>/<service>/<environment>"},
        },
    },
}


class ToolError(Exception):
    """A refusal the user should read as is (validation, exists, permission)."""


# --------------------------------------------------------------------- GUARD-03
_PATTERNS = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "an AWS access key"),
    (re.compile(r"-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----"), "a PEM block"),
    (re.compile(r"\b(?:ghp|gho|ghs|github_pat|xox[abpr]|sk|hv[sbr])[-_.][A-Za-z0-9_\-.]{12,}"),
     "an API token"),
    (re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{4,}"),
     "an assignment of a secret value"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."), "a JWT"),
]
_SPLIT = re.compile(r"[\s/?&=:,;()\[\]{}<>\"'`]+")


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def credential_like(text: str) -> str | None:
    """What kind of credential `text` seems to contain, or None (GUARD-03)."""
    for pattern, what in _PATTERNS:
        if pattern.search(text):
            return what
    for tok in _SPLIT.split(text):
        if len(tok) >= 20 and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok) \
                and _entropy(tok) >= 3.5:
            return "a long random-looking string"
    return None


def _strings(args: dict) -> list[tuple[str, str]]:
    out = [(k, v) for k, v in args.items() if isinstance(v, str)]
    for i, key in enumerate(args.get("keys") or []):
        if isinstance(key, dict):
            out += [(f"keys[{i}].{k}", v) for k, v in key.items() if isinstance(v, str)]
    return out


# --------------------------------------------------------------------- REQ-02
def validate(args: dict) -> dict:
    """The checked request, or ToolError naming every problem with a valid example."""
    problems: list[str] = []
    for field, text in _strings(args):
        what = credential_like(text)
        if what:
            raise ToolError(
                f"Refused: {field} looks like it contains {what}. Secret values are never "
                "taken from chat: use source 'generate' (the server makes the value) or 'ui' "
                "(fill it in the OpenBao UI). Remove it and try again; nothing was written.")
    unknown = set(args) - FIELDS
    if unknown:
        problems.append(f"unknown fields {sorted(unknown)} (no value fields exist)")

    def check(field: str, ok: bool, example: str) -> None:
        if not ok:
            problems.append(f"{field}: e.g. {example}")

    product, service = args.get("product"), args.get("service")
    env, desc = args.get("environment"), args.get("description")
    team, jira = args.get("team"), args.get("jira_ticket")
    check("product", isinstance(product, str) and bool(NAME_RE.match(product)),
          "payments (lowercase letters, digits, '-', 2-31 chars)")
    check("service", isinstance(service, str) and bool(NAME_RE.match(service)),
          "checkout-api (lowercase letters, digits, '-', 2-31 chars)")
    check("environment", env in ENVIRONMENTS, "dev, staging or prod")
    check("description", isinstance(desc, str) and 10 <= len(desc.strip()) <= 300,
          "'Database credentials for the checkout API' (10-300 chars)")
    check("team", isinstance(team, str) and bool(TEAM_RE.match(team)), "platform")
    check("jira_ticket", isinstance(jira, str) and bool(JIRA_RE.match(jira)), "PAY-1234")

    keys_in = args.get("keys")
    keys: list[dict] = []
    if not isinstance(keys_in, list) or not 1 <= len(keys_in) <= MAX_KEYS:
        problems.append(f"keys: 1-{MAX_KEYS} entries, e.g. "
                        "[{\"name\": \"DB_PASSWORD\", \"source\": \"generate\", \"kind\": \"password\"}]")
    else:
        seen: set[str] = set()
        for i, k in enumerate(keys_in):
            if not isinstance(k, dict):
                problems.append(f"keys[{i}]: an object with name and source")
                continue
            extra = set(k) - KEY_FIELDS
            if extra:
                problems.append(f"keys[{i}]: unknown fields {sorted(extra)} (no value fields exist)")
            name, source, kind = k.get("name"), k.get("source"), k.get("kind")
            check(f"keys[{i}].name", isinstance(name, str) and bool(KEY_RE.match(name)),
                  "DB_PASSWORD (letters, digits, '_', not starting with a digit)")
            if isinstance(name, str):
                if name in seen:
                    problems.append(f"keys[{i}].name: {name} appears twice")
                seen.add(name)
            check(f"keys[{i}].source", source in ("generate", "ui"), "generate or ui")
            if source == "generate":
                kind = kind or "password"
                check(f"keys[{i}].kind", kind in KINDS, "password, hex or uuid")
            elif source == "ui" and kind is not None:
                problems.append(f"keys[{i}].kind: only for source 'generate'")
            keys.append({"name": name, "source": source,
                         "kind": kind if source == "generate" else None})

    sync = args.get("sync_aws")
    check("sync_aws", isinstance(sync, bool), "true or false")
    aws_name = ""
    if sync is True:
        aws_name = args.get("aws_secret_name") or f"openbao/{product}/{service}/{env}"
        check("aws_secret_name", isinstance(aws_name, str) and bool(AWS_RE.match(aws_name))
              and ".." not in aws_name, f"openbao/{product}/{service}/{env} (must start with openbao/)")
    elif args.get("aws_secret_name"):
        problems.append("aws_secret_name: only when sync_aws is true")

    if problems:
        raise ToolError("Invalid request, nothing was written:\n- " + "\n- ".join(problems))
    return {"product": product, "service": service, "environment": env,
            "description": desc.strip(), "team": team, "jira_ticket": jira, "keys": keys,
            "sync_aws": sync, "aws_secret_name": aws_name}


# --------------------------------------------------------------------- REQ-04
_ALPHABET = string.ascii_letters + string.digits + "-_.~!#%^*+="


def generate(kind: str) -> str:
    if kind == "hex":
        return secrets.token_hex(32)
    if kind == "uuid":
        return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    # password: 32 chars with at least one lower, upper and digit.
    while True:
        v = "".join(secrets.choice(_ALPHABET) for _ in range(32))
        if any(c.islower() for c in v) and any(c.isupper() for c in v) \
                and any(c.isdigit() for c in v):
            return v


def needed_group(env: str) -> str:
    """REQ-06: who may create where (D-25)."""
    if env == "prod":
        return "Creating in prod needs the Identity Center group openbao-admins."
    return ("Creating in dev or staging needs the Identity Center group "
            "openbao-secrets-writers (or openbao-admins).")


# --------------------------------------------------------------------- REQ-03..07
def create_secret(settings: Settings, who: Identity, session: Session, args: dict) -> dict:
    req = validate(args)
    m = settings.apps_mount
    rel = f"{req['product']}/{req['service']}/{req['environment']}"
    denied = needed_group(req["environment"])

    # REQ-07: refuse an existing path, saying whose it is.
    try:
        existing = session.read(f"{m}/metadata/{rel}")
    except OpenBaoError as e:
        if e.status == 403:
            raise ToolError(f"Refused by OpenBao (403) for {m}/{rel}. {denied}") from None
        raise
    if existing is not None:
        cm = (existing.get("data") or {}).get("custom_metadata") or {}
        raise ToolError(
            f"{m}/{rel} already exists, created by {cm.get('created_by', 'unknown')} for "
            f"{cm.get('jira_ticket', 'no ticket')}. Nothing was changed.")

    data: dict[str, str] = {}
    for k in req["keys"]:
        data[k["name"]] = generate(k["kind"]) if k["source"] == "generate" else PLACEHOLDER
    try:
        session.write(f"{m}/data/{rel}", {"options": {"cas": 0}, "data": data})
    except OpenBaoError as e:
        if e.status == 403:
            raise ToolError(f"Refused by OpenBao (403) for {m}/{rel}. {denied}") from None
        if e.status == 400 and "check-and-set" in e.reason:
            raise ToolError(f"{m}/{rel} already exists (created a moment ago). "
                            "Nothing was changed.") from None
        raise
    finally:
        data.clear()                             # drop the values as soon as they're sent

    metadata = {
        "description": req["description"],
        "team": req["team"],
        "jira_ticket": req["jira_ticket"],
        "created_by": who.email,
        "sync_aws": "true" if req["sync_aws"] else "false",
        "aws_secret_name": req["aws_secret_name"],
        "schema": SCHEMA,
    }
    for k in req["keys"]:                         # one entry per key: values are <= 512 bytes
        metadata[f"key.{k['name']}"] = (f"generated:{k['kind']}" if k["source"] == "generate"
                                        else "pending-ui")
    try:
        session.write(f"{m}/metadata/{rel}", {"custom_metadata": metadata})
    except OpenBaoError as e:
        raise ToolError(
            f"The secret {m}/{rel} was created, but its metadata could not be written "
            f"(OpenBao {e.status}: {e.reason}). It has no description, team, ticket or sync "
            "setting yet: ask an OpenBao admin to add them. Don't create it again.") from None

    ui = settings.ui_url
    pending = [k["name"] for k in req["keys"] if k["source"] == "ui"]
    out: dict[str, Any] = {
        "created": f"{m}/{rel}",
        "keys": [{"name": k["name"],
                  "set": f"generated ({k['kind']})" if k["source"] == "generate"
                  else "placeholder: set it in the OpenBao UI"} for k in req["keys"]],
        "metadata": metadata,
        "aws_secret_name": req["aws_secret_name"] or None,
        "ui_link": f"{ui}/ui/vault/secrets/{m}/show/{rel}" if ui else None,
    }
    if pending:
        out["set_values_here"] = f"{ui}/ui/vault/secrets/{m}/edit/{rel}" if ui else None
        out["note"] = (f"Set {', '.join(pending)} in the OpenBao UI (create a new version). "
                       + ("The AWS sync waits until every value is set." if req["sync_aws"]
                          else ""))
    return out

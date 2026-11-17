"""The MCP tools. Each takes the verified Identity and that user's OpenBao Session."""
from __future__ import annotations

from .auth import Identity
from .config import Settings
from .openbao import Session

ENVIRONMENTS = ("dev", "staging", "prod")
# Placeholder product/service used only to ask OpenBao what this token may do per
# environment (policies match apps/data/+/+/<env>).
_PROBE = "_probe/_probe"

WHOAMI = {
    "name": "whoami",
    "description": (
        "Show who you (the signed-in user) are to OpenBao: email, Identity Center groups, "
        "OpenBao policies, and whether you may create secrets in dev, staging and prod "
        "under apps/ and search them. Use before creating a secret or to explain a denial."
    ),
    "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
}

# MCP annotations per tool: whoami only reads; create_secret writes (create-only, never
# overwrites), so it isn't idempotent and isn't destructive.
ANNOTATIONS = {
    "whoami": {"read_only_hint": True, "open_world_hint": False},
    "create_secret": {"read_only_hint": False, "destructive_hint": False,
                      "idempotent_hint": False, "open_world_hint": False},
}

from .create import CREATE_SECRET  # noqa: E402

TOOLS = [WHOAMI, CREATE_SECRET]


def whoami(settings: Settings, who: Identity, session: Session) -> dict:
    """Spec 001 REQ-04: identity and rights under apps/, nothing else."""
    m = settings.apps_mount
    data_paths = {env: f"{m}/data/{_PROBE}/{env}" for env in ENVIRONMENTS}
    search_path = f"{m}/metadata/"
    caps = session.capabilities(list(data_paths.values()) + [search_path])
    return {
        "email": who.email,
        "groups": list(who.groups),
        "openbao_policies": list(session.policies),
        "may_create": {env: "create" in caps[p] for env, p in data_paths.items()},
        "may_search": "list" in caps[search_path],
        "secrets_path": f"{m}/<product>/<service>/<environment>",
    }

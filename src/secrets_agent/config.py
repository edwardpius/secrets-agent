"""Settings from the environment (spec 001)."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    openbao_addr: str                  # e.g. https://openbao-active.openbao.svc:8200
    openbao_ca: str | None             # CA bundle path; None = system roots
    cognito_issuer: str                # https://cognito-idp.<region>.amazonaws.com/<pool>
    cognito_client_id: str             # the kagent client: audience of the ID token
    jwt_mount: str = "jwt-mcp"
    jwt_role: str = "mcp-user"
    apps_mount: str = "apps"
    ui_url: str = ""                   # public OpenBao URL for links, e.g. https://openbao.example.com

    @classmethod
    def from_env(cls) -> "Settings":
        def need(name: str) -> str:
            v = os.environ.get(name, "").strip()
            if not v:
                raise SystemExit(f"secrets-mcp: {name} must be set")
            return v
        return cls(
            openbao_addr=need("OPENBAO_ADDR").rstrip("/"),
            openbao_ca=os.environ.get("OPENBAO_CACERT") or None,
            cognito_issuer=need("COGNITO_ISSUER").rstrip("/"),
            cognito_client_id=need("COGNITO_CLIENT_ID"),
            jwt_mount=os.environ.get("OPENBAO_JWT_MOUNT", "jwt-mcp"),
            jwt_role=os.environ.get("OPENBAO_JWT_ROLE", "mcp-user"),
            apps_mount=os.environ.get("OPENBAO_APPS_MOUNT", "apps"),
            ui_url=os.environ.get("OPENBAO_UI_URL", "").rstrip("/"),
        )

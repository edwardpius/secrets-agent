# Mission

**One line:** Ask for a secret in plain language, and get it created in the right place
with the right owner, or found, without a secret value ever passing through the chat.

## Summary

secrets-agent is a kagent agent on Edward's AI Hub with its own MCP server. It creates
secrets at `apps/<product>/<service>/<environment>` in OpenBao, with a description, the
owning team, a (fictitious) JIRA ticket and an optional sync to AWS Secrets Manager, and it
searches them by key (path, team, ticket) or by meaning. It always acts **as the signed-in
user**: OpenBao enforces their Identity Center groups and records them in its audit log.

## Users

- **Engineers and developers on the hub** who need a secret created or found, signed in
  through IAM Identity Center.
- **Platform admins** who want secret creation to follow one hierarchy and leave an audit
  trail (who, why, which ticket).

## Problem

Creating a secret by hand means knowing the mount, the path convention, the metadata to
fill in and, for AWS consumers, how the sync works. People skip the metadata, put secrets
in the wrong place, and can't find existing ones, so they create duplicates.

## Never

- **Never handle a secret value in the conversation**: it doesn't accept values typed in
  chat, never shows one, and never puts one in a tool result, trace or log. Values are
  generated inside the MCP server or entered in the OpenBao UI.
- **Never act with rights of its own**: every OpenBao call uses the calling user's token.
- **Never overwrite or delete** a secret, and never write outside `apps/`.
- **Never decide permissions itself**: OpenBao policies decide; the agent explains a denial.

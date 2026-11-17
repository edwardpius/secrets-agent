# secrets-agent

The second agent on [Edward's AI Hub](https://github.com/edwardpius/ai-hub): a kagent agent
and its MCP server that **create and search secrets in OpenBao on behalf of the signed-in
user**. Secrets live at `apps/<product>/<service>/<environment>`. Every call runs with the
user's own short-lived OpenBao token, so OpenBao, not the agent, decides who may create what
(by IAM Identity Center group), and OpenBao's audit log names the real user.

| Start here | |
|---|---|
| [product/mission.md](product/mission.md) | Why it exists, for whom, and what it will never do |
| [product/roadmap.md](product/roadmap.md) | Phases and progress (the only place status lives) |
| [product/tech-stack.md](product/tech-stack.md) | Principles, stack, open decisions |
| [product/decisions.md](product/decisions.md) | Why things are the way they are |
| [WORKFLOW.md](WORKFLOW.md) | How a feature goes from idea to shipped |

Platform pieces (OpenBao mount and policies, ECR repository) live in openbao-platform;
the agent's Kubernetes manifests live in the ai-hub repo (`deploy/`), synced by Argo CD.

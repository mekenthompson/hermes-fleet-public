"""Claude Code subscription provider via ACP.

Adapted from https://github.com/mvdbastos/hermes-acp-agents at source
revision 0526610a3945cc376ac517b63ca358a5b838a2fc. The Fleet variant
fails closed to the Claude subscription login by removing API, proxy,
cloud-provider, and model-override environment variables before launch.
"""

from agent.acp_agent_registry import ACPAgentEntry, register_acp_agent
from providers import register_provider
from providers.base import ProviderProfile

_SUBSCRIPTION_SAFETY_UNSET = (
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SSE_PORT",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_CUSTOM_HEADERS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
)

register_acp_agent(
    "claude",
    ACPAgentEntry(
        command="claude-agent-acp",
        env_unset=_SUBSCRIPTION_SAFETY_UNSET,
        display_name="Claude Code",
        install_hint="Install @agentclientprotocol/claude-agent-acp 0.70.0.",
    ),
)


class ClaudeACPProfile(ProviderProfile):
    """Claude Code external-process provider."""

    def fetch_models(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 8.0,
    ) -> list[str] | None:
        return None


register_provider(
    ClaudeACPProfile(
        name="claude-acp",
        aliases=("claude-code-acp",),
        api_mode="chat_completions",
        display_name="Claude Code ACP",
        description="Claude Code subscription via the maintained ACP adapter",
        env_vars=("CLAUDE_CODE_OAUTH_TOKEN",),
        base_url="acp://claude",
        auth_type="external_process",
        supports_health_check=False,
        fallback_models=("default", "opus[1m]", "sonnet", "haiku"),
    )
)

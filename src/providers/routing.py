"""Map request paths to upstream API bases."""

from ..config import config


def upstream_base_for_path(path: str) -> str:
    """Return upstream API origin (no trailing slash) for a proxied path."""
    normalized = path.lstrip("/")
    if normalized == "v1/chat/completions" or normalized.startswith("v1/chat/completions/"):
        return config.OPENAI_API_URL.rstrip("/")
    return config.ANTHROPIC_API_URL.rstrip("/")

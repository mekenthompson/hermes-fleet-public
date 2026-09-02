"""Perplexity Search API plugin, search only."""
from __future__ import annotations

from .provider import PerplexityWebSearchProvider


def register(ctx) -> None:
    ctx.register_web_search_provider(PerplexityWebSearchProvider())

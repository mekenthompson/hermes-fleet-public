"""Perplexity Search API provider for web_search only."""
from __future__ import annotations

from typing import Any

import httpx

from agent.web_search_provider import WebSearchProvider, get_provider_env

_SEARCH_URL = "https://api.perplexity.ai/search"
_TIMEOUT_SECS = 30


class PerplexityWebSearchProvider(WebSearchProvider):
    @property
    def name(self) -> str:
        return "perplexity"

    @property
    def display_name(self) -> str:
        return "Perplexity Search"

    def is_available(self) -> bool:
        return bool(get_provider_env("PERPLEXITY_API_KEY"))

    def supports_search(self) -> bool:
        return True

    def supports_extract(self) -> bool:
        return False

    def get_setup_schema(self) -> dict[str, Any]:
        return {
            "name": self.display_name,
            "badge": "paid · key · search only",
            "tag": "Structured web results from the Perplexity Search API.",
            "env_vars": [
                {
                    "key": "PERPLEXITY_API_KEY",
                    "prompt": "Perplexity API key",
                    "url": "https://www.perplexity.ai/settings/api",
                }
            ],
        }

    def search(self, query: str, limit: int = 5) -> dict[str, Any]:
        if not query or not query.strip():
            return {"success": False, "error": "Empty search query"}
        api_key = get_provider_env("PERPLEXITY_API_KEY")
        if not api_key:
            return {"success": False, "error": "PERPLEXITY_API_KEY is not set"}
        count = max(1, min(int(limit), 20))
        try:
            response = httpx.post(
                _SEARCH_URL,
                json={"query": query.strip(), "max_results": count},
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                timeout=_TIMEOUT_SECS,
            )
        except httpx.TimeoutException:
            return {"success": False, "error": "Perplexity search timed out"}
        except httpx.HTTPError as exc:
            return {"success": False, "error": f"Perplexity search HTTP error: {exc.__class__.__name__}"}
        if response.status_code >= 400:
            return {"success": False, "error": f"Perplexity search failed with HTTP {response.status_code}"}
        try:
            payload = response.json()
        except ValueError:
            return {"success": False, "error": "Perplexity search returned non-JSON"}
        rows = payload.get("results") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            rows = []
        web = []
        for position, row in enumerate(rows, start=1):
            if isinstance(row, dict):
                web.append({
                    "title": row.get("title") or "",
                    "url": row.get("url") or "",
                    "description": row.get("snippet") or row.get("description") or "",
                    "position": position,
                })
        return {"success": True, "data": {"web": web}}

    def extract(self, urls: list[str], **kwargs: Any) -> list[dict[str, Any]]:
        return [{
            "url": url,
            "title": "",
            "content": "",
            "error": "Perplexity provider is search-only; configure a web extraction provider",
        } for url in urls]

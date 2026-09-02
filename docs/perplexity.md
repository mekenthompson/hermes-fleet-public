# Perplexity web provider

The Fleet image bundles a generic Perplexity Search API provider. It implements `web_search` only and does not provide URL extraction.

The provider is unavailable unless the runtime receives `PERPLEXITY_API_KEY` through its secret-management boundary. The image contains no API key, secret reference, profile binding, or deployment routing.

Select it with the Hermes configuration key:

```yaml
web:
  search_backend: perplexity
```

Configure a separate `web.extract_backend` when URL extraction is required. The provider calls Perplexity's documented `POST https://api.perplexity.ai/search` endpoint, caps `max_results` to the API range of 1–20, and maps ranked `title`, `url`, and `snippet` fields into Hermes web results.

Official API documentation: <https://docs.perplexity.ai/api-reference/search-post>

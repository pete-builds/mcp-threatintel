"""Ahmia.fi dark web search client.

Ahmia indexes .onion sites and provides a clearnet search interface.
No JSON API exists, so we scrape HTML results. This is fragile by nature
but it's the only free dark web search option.

No API key required.
"""

import logging
import re

from .base import BaseClient

logger = logging.getLogger("threatintel.ahmia")


class AhmiaClient(BaseClient):
    """Ahmia.fi dark web search via HTML scraping."""

    def __init__(self):
        super().__init__("https://ahmia.fi", rate_limit=2.0)

    async def search(self, query: str, max_results: int = 20) -> dict:
        """Search the dark web via Ahmia.

        Args:
            query: Search terms.
            max_results: Max results to return (default 20).

        Returns:
            Dict with results containing title, url (.onion), and description.
        """
        # Ahmia returns HTML, so we need to fetch raw and parse
        await self._rate_limit()
        url = f"{self.base_url}/search/"
        for attempt in range(2):
            try:
                resp = await self._client.get(url, params={"q": query})
                resp.raise_for_status()
                html = resp.text
                break
            except Exception:
                if attempt == 0:
                    continue
                raise

        results = _parse_results(html, max_results)
        logger.info("ahmia: query=%r results=%d", query, len(results))

        return {
            "query": query,
            "source": "ahmia.fi (dark web)",
            "result_count": len(results),
            "results": results,
        }


def _parse_results(html: str, max_results: int) -> list[dict]:
    """Parse Ahmia search results from HTML.

    Ahmia results are in <li class="result"> elements containing:
    - <a> with href (the .onion URL, often via redirect)
    - <h4> or heading with title
    - <p> or description text
    """
    results = []

    # Pattern: find result blocks. Ahmia uses <li class="result"> or similar
    # Extract onion URLs, titles, and descriptions
    result_blocks = re.findall(
        r'<li[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</li>',
        html,
        re.DOTALL,
    )

    if not result_blocks:
        # Fallback: try to find any .onion links with surrounding context
        onion_pattern = r'<a[^>]*href="([^"]*)"[^>]*>([^<]*)</a>'
        links = re.findall(onion_pattern, html)
        for href, title in links:
            onion_url = _extract_onion_url(href)
            if onion_url and title.strip():
                results.append({
                    "title": title.strip(),
                    "url": onion_url,
                    "description": "",
                })
                if len(results) >= max_results:
                    break
        return results

    for block in result_blocks:
        if len(results) >= max_results:
            break

        # Extract URL (may be a redirect URL containing the .onion)
        href_match = re.search(r'href="([^"]+)"', block)
        title_match = re.search(r'<h4[^>]*>(.*?)</h4>', block, re.DOTALL)
        if not title_match:
            title_match = re.search(r'<a[^>]*>([^<]+)</a>', block)
        desc_match = re.search(r'<p[^>]*>(.*?)</p>', block, re.DOTALL)

        if not href_match:
            continue

        href = href_match.group(1)
        onion_url = _extract_onion_url(href)
        title = _clean_html(title_match.group(1)) if title_match else ""
        description = _clean_html(desc_match.group(1)) if desc_match else ""

        if onion_url or href:
            results.append({
                "title": title,
                "url": onion_url or href,
                "description": description,
            })

    return results


def _extract_onion_url(href: str) -> str | None:
    """Extract .onion URL from an Ahmia redirect link or direct link."""
    # Ahmia sometimes wraps URLs in redirects like /search/redirect?search_url=...
    if "redirect" in href and "search_url=" in href:
        match = re.search(r'search_url=([^&]+)', href)
        if match:
            from urllib.parse import unquote
            return unquote(match.group(1))

    # Direct .onion link
    if ".onion" in href:
        return href

    return None


def _clean_html(text: str) -> str:
    """Strip HTML tags and clean whitespace."""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

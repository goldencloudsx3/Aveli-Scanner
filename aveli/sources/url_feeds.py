"""
Supplementary URL feed sources.

  - URLScan.io live search
  - OpenPhish feed
  - Active domain probe (Tranco + HackerTarget subdomains, loops continuously)
"""

import asyncio
import json
import logging

import aiohttp

logger = logging.getLogger("aveli.url_feeds")


# ---------------------------------------------------------------------------
# URLScan.io — public search, no auth needed for basic queries
# ---------------------------------------------------------------------------

async def stream_urlscan(
    queue: asyncio.Queue,
    query: str = "page.status:200 AND NOT page.url:google.com",
    max_results: int = 200,
    interval_seconds: int = 300,
    max_queue_size: int = 5000,
) -> None:
    """Poll URLScan.io for recently scanned pages matching the query."""
    base_url = "https://urlscan.io/api/v1/search/"
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                params = {"q": query, "size": str(max_results), "sort": "_score"}
                async with session.get(base_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for result in data.get("results", []):
                            url = result.get("page", {}).get("url", "")
                            if url and queue.qsize() < max_queue_size:
                                await queue.put(url)
                        logger.debug("URLScan.io yielded %d URLs", len(data.get("results", [])))
                    elif resp.status == 429:
                        logger.debug("URLScan rate-limited, backing off 60s")
                        await asyncio.sleep(60)
                        continue
            except Exception as exc:
                logger.debug("URLScan feed error: %s", exc)

            await asyncio.sleep(interval_seconds)


# ---------------------------------------------------------------------------
# OpenPhish — free phishing URL feed (updated every 12h)
# ---------------------------------------------------------------------------

async def stream_openphish(
    queue: asyncio.Queue,
    interval_seconds: int = 43200,
    max_queue_size: int = 5000,
) -> None:
    """Fetch OpenPhish feed and enqueue phishing URLs for credential-exposure scanning."""
    feed_url = "https://openphish.com/feed.txt"
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                async with session.get(feed_url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        count = 0
                        for line in text.splitlines():
                            url = line.strip()
                            if url.startswith("http") and queue.qsize() < max_queue_size:
                                await queue.put(url)
                                count += 1
                        logger.info("OpenPhish feed loaded %d URLs", count)
            except Exception as exc:
                logger.debug("OpenPhish feed error: %s", exc)

            await asyncio.sleep(interval_seconds)


# ---------------------------------------------------------------------------
# Active domain probe — loops continuously
# ---------------------------------------------------------------------------

_PROBE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-config.php",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/database.yml",
    "/secrets.yml",
    "/credentials.json",
    "/.npmrc",
    "/.aws/credentials",
    "/backup.sql",
    "/dump.sql",
    "/.htpasswd",
    "/phpinfo.php",
    "/adminer.php",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/api/v1/users",
    "/api/users",
    "/debug",
    "/console",
    "/server-status",
    "/id_rsa",
    "/private.key",
    "/",
]

# Broad set of domains likely to have misconfigs — mix of CMS/framework
# heavy sites, hosting providers, and high-traffic targets.
# These are probed every cycle so any newly exposed file gets caught fast.
_SEED_DOMAINS = [
    # WordPress / PHP heavy (highest misconfiguration rate)
    "wordpress.com", "wp.com", "wix.com", "squarespace.com",
    "godaddy.com", "bluehost.com", "siteground.com", "hostgator.com",
    "dreamhost.com", "a2hosting.com", "inmotionhosting.com",
    # Dev / cloud platforms
    "github.com", "gitlab.com", "bitbucket.org",
    "heroku.com", "netlify.com", "vercel.com", "render.com",
    "digitalocean.com", "linode.com", "vultr.com",
    # E-commerce
    "shopify.com", "bigcommerce.com", "woocommerce.com", "magento.com",
    "prestashop.com", "opencart.com",
    # Crypto / finance
    "coinbase.com", "binance.com", "kraken.com", "opensea.io",
    "blockchain.com", "etherscan.io", "metamask.io",
    # APIs / SaaS often left misconfigured
    "stripe.com", "paypal.com", "twilio.com", "sendgrid.com",
    "mailchimp.com", "hubspot.com", "zendesk.com", "freshdesk.com",
    # CMS / frameworks
    "drupal.org", "joomla.org", "typo3.org", "contao.org",
    # Common self-hosted stacks
    "jenkins.io", "grafana.com", "kibana.io", "portainer.io",
]


async def _fetch_tranco_domains(session: aiohttp.ClientSession, count: int = 1000) -> list[str]:
    """Fetch top domains from the Tranco list."""
    try:
        async with session.get(
            "https://tranco-list.eu/api/lists/daily",
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                list_id = data.get("list_id", "")
                if list_id:
                    list_url = f"https://tranco-list.eu/download_daily/{list_id}/{count}"
                    async with session.get(list_url) as lr:
                        if lr.status == 200:
                            text = await lr.text()
                            domains = []
                            for line in text.splitlines()[:count]:
                                parts = line.split(",")
                                if len(parts) >= 2:
                                    domains.append(parts[1].strip())
                            logger.info("Tranco: loaded %d domains", len(domains))
                            return domains
    except Exception as exc:
        logger.debug("Tranco fetch error: %s", exc)
    return []


async def _fetch_hackertarget_subdomains(
    session: aiohttp.ClientSession, domain: str
) -> list[str]:
    """
    Use HackerTarget's free API to get subdomains for a domain.
    Returns up to ~100 subdomains per domain, no auth required.
    """
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "error check your search" in text.lower() or "api count exceeded" in text.lower():
                    return []
                subdomains = []
                for line in text.strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip()
                        if sub and "." in sub:
                            subdomains.append(sub)
                return subdomains
    except Exception as exc:
        logger.debug("HackerTarget error for %s: %s", domain, exc)
    return []


async def probe_top_sites(
    queue: asyncio.Queue,
    max_queue_size: int = 5000,
    interval_seconds: int = 600,
) -> None:
    """
    Continuously probe a large set of domains with sensitive-path requests.

    Each cycle:
      1. Fetches the Tranco top-1000 domain list
      2. Combines with the hardcoded seed list
      3. For each domain, queues probes for all sensitive paths
      4. Sleeps interval_seconds then repeats

    By looping, fresh targets keep entering the queue even when other
    sources (certstream, URLScan) are unavailable.
    """
    timeout = aiohttp.ClientTimeout(total=20)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            domains = await _fetch_tranco_domains(session, count=1000)
            if not domains:
                logger.debug("Tranco unavailable, using seed list")
                domains = list(_SEED_DOMAINS)
            else:
                # Merge seed domains to always cover high-value targets
                domain_set = set(domains)
                for d in _SEED_DOMAINS:
                    if d not in domain_set:
                        domains.append(d)

            queued = 0
            for domain in domains:
                for path in _PROBE_PATHS:
                    if queue.qsize() >= max_queue_size:
                        break
                    await queue.put(f"https://{domain}{path}")
                    queued += 1

            logger.info(
                "probe_top_sites: queued %d probe URLs across %d domains",
                queued, len(domains),
            )
            await asyncio.sleep(interval_seconds)

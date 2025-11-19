import requests
import json
import os
import sys
import time
import logging
import re
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Get env vars from GitHub secrets
api_token = os.environ.get('CLOUDFLARE_API_TOKEN')
account_id = os.environ.get('CLOUDFLARE_ACCOUNT_ID')

if not api_token or not account_id:
    logger.error("Missing API token or account ID.")
    sys.exit(1)

# Configuration
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))
MAX_RETRIES = 3
BACKOFF_FACTOR = 5
CHUNK_SIZE = 1000
MAX_LISTS_WARNING = 900
API_DELAY = 0.25  # Small delay between requests to avoid rate limiting

# API base URL
base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

session = requests.Session()
session.headers.update(headers)

def api_request(method: str, url: str, data: Optional[Dict] = None, 
                retries: int = MAX_RETRIES, backoff_factor: int = BACKOFF_FACTOR, 
                timeout: int = REQUEST_TIMEOUT) -> requests.Response:
    """Make API request with retry logic and rate limit handling."""
    last_exception = None
    for attempt in range(1, retries + 1):
        try:
            kwargs = {"timeout": timeout}
            if data:
                kwargs["json"] = data

            response = getattr(session, method.lower())(url, **kwargs)

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', backoff_factor * (2 ** (attempt - 1))))
                logger.warning(f"Rate limited (429). Waiting {retry_after}s before retry {attempt}/{retries}...")
                time.sleep(retry_after)
                continue

            if response.status_code >= 500 and attempt < retries:
                sleep_time = backoff_factor * (2 ** (attempt - 1))
                logger.warning(f"Server error {response.status_code}. Retry {attempt}/{retries} in {sleep_time}s...")
                time.sleep(sleep_time)
                continue

            return response
            
        except requests.exceptions.RequestException as e:
            last_exception = e
            if attempt < retries:
                sleep_time = backoff_factor * (2 ** (attempt - 1))
                logger.warning(f"Request exception: {e}. Retry {attempt}/{retries} in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                logger.error(f"All retries exhausted for {method} {url}")
                raise last_exception
    
    # This should never be reached, but just in case
    if last_exception:
        raise last_exception
    raise Exception(f"Unexpected error in api_request for {method} {url}")

def check_api_response(response: requests.Response, action: str) -> Dict:
    """Validate API response and return JSON data."""
    if response.status_code != 200:
        logger.error(f"Error {action}: {response.status_code} - {response.text}")
        raise Exception(f"API error during {action}: {response.status_code}")
    
    data = response.json()
    if not data.get('success', False):
        logger.error(f"API success false during {action}: {json.dumps(data)}")
        raise Exception(f"API returned success=false during {action}")
    
    return data

def is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    if not domain or len(domain) > 253:
        return False
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain.lower()))

def chunker(seq: List[str], size: int):
    """Split a sequence into chunks of specified size."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]

def get_all_paginated(endpoint: str, per_page: int = 100) -> List[Dict]:
    """Fetch all items from a paginated endpoint."""
    all_items = []
    page = 1
    
    try:
        while True:
            url = f"{endpoint}?per_page={per_page}&page={page}"
            response = api_request('GET', url)
            data = check_api_response(response, f"getting {endpoint} page {page}")
            
            # FIXED: Handle None values from API (use 'or' instead of default parameter)
            items = data.get('result') or []
            all_items.extend(items)
            
            # FIXED: Handle None for result_info
            result_info = data.get('result_info') or {}
            total_count = result_info.get('total_count', 0)
            
            # Check if we've fetched everything
            if page * result_info.get('per_page', per_page) >= total_count or not items:
                break
            
            page += 1
            time.sleep(API_DELAY)  # Small delay between pages
        
        logger.info(f"Fetched {len(all_items)} items from {endpoint} ({page} page(s))")
        return all_items
        
    except Exception as e:
        logger.error(f"Pagination failed for {endpoint} at page {page}: {e}", exc_info=True)
        raise

# Define blocklists with names, primary URLs, and backup URLs
blocklists: List[Dict[str, str]] = [
    {
        "name": "Hagezi Pro++",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt"
    },
    {
        "name": "Hagezi-DynDNS",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/dyndns-onlydomains.txt"
    },
    {
        "name": "Samsung-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.samsung-onlydomains.txt"
    },
    {
        "name": "Vivo-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.vivo-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.vivo-onlydomains.txt"
    },
    {
        "name": "OppoRealme-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.oppo-realme-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.oppo-realme-onlydomains.txt"
    },
    {
        "name": "Xiaomi-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.xiaomi-onlydomains.txt"
    },
    {
        "name": "TikTok-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.tiktok-onlydomains.txt"
    }
]

# Derive cleanup names dynamically from blocklists
old_policy_names = [f"Block {bl['name']}" for bl in blocklists]
old_prefixes = [f"{bl['name'].replace(' ', '_')}_List_" for bl in blocklists]

logger.info("Starting Cloudflare Gateway Adblock Update...\n")

# === GLOBAL CLEANUP (Safety Net for Orphaned Resources) ===
logger.info("Performing global cleanup of orphaned resources...")
try:
    all_rules = get_all_paginated(f"{base_url}/rules")
    all_lists = get_all_paginated(f"{base_url}/lists")
    
    # Cleanup orphaned policies
    orphan_policies = 0
    for rule in all_rules:
        if rule['name'] in old_policy_names:
            try:
                api_request('DELETE', f"{base_url}/rules/{rule['id']}")
                logger.info(f"Cleaned up orphaned policy: {rule['name']}")
                orphan_policies += 1
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Could not delete policy {rule['name']}: {e}")
    
    # Cleanup orphaned lists
    orphan_lists = 0
    for lst in all_lists:
        if any(lst['name'].startswith(prefix) for prefix in old_prefixes):
            try:
                api_request('DELETE', f"{base_url}/lists/{lst['id']}")
                logger.info(f"Cleaned up orphaned list: {lst['name']}")
                orphan_lists += 1
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Could not delete list {lst['name']}: {e}")
    
    logger.info(f"Global cleanup complete: {orphan_policies} policies, {orphan_lists} lists removed\n")
    
except Exception as e:
    logger.warning(f"Global cleanup failed: {e}. Continuing anyway...\n")

# === CACHE CURRENT STATE (Reduce API Calls) ===
logger.info("Caching current rules and lists...")
try:
    cached_rules = get_all_paginated(f"{base_url}/rules")
    cached_lists = get_all_paginated(f"{base_url}/lists")
    logger.info(f"Cached {len(cached_rules)} rules and {len(cached_lists)} lists\n")
except Exception as e:
    logger.error(f"Failed to cache rules/lists: {e}", exc_info=True)
    sys.exit(1)

# === PROCESS EACH BLOCKLIST ===
stats = {
    "filters_processed": 0,
    "total_domains": 0,
    "lists_created": 0,
    "policies_created": 0,
    "errors": []
}

for bl in blocklists:
    try:
        filter_name = bl["name"]
        primary_url = bl["url"]
        backup_url = bl.get("backup_url")
        list_prefix = f"{filter_name.replace(' ', '_')}_List_"
        policy_name = f"Block {filter_name}"

        logger.info(f"{'='*60}")
        logger.info(f"Processing filter: {filter_name}")
        logger.info(f"{'='*60}")

        # Step 1: Fetch the blocklist (use plain requests, not session)
        fetched = False
        content = None
        for url in [primary_url, backup_url]:
            if url is None:
                continue
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    content = response.text
                    fetched = True
                    logger.info(f"✓ Successfully fetched from {url}")
                    break
                else:
                    logger.warning(f"✗ Failed to fetch from {url}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"✗ Error fetching from {url}: {e}")

        if not fetched:
            logger.error(f"✗ Could not fetch {filter_name} from any source. Skipping.")
            stats["errors"].append(filter_name)
            continue

        # Step 2: Process domains (validate, deduplicate)
        lines = content.splitlines()
        domains = set()
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and is_valid_domain(line):
                domains.add(line)

        domains = list(domains)
        logger.info(f"✓ Processed {len(domains):,} unique valid domains")
        stats["total_domains"] += len(domains)

        if not domains:
            logger.warning(f"✗ No valid domains found. Skipping.")
            continue

        # Step 3: Split into chunks
        chunks = list(chunker(domains, CHUNK_SIZE))
        logger.info(f"✓ Split into {len(chunks)} chunk(s)")

        if len(chunks) > MAX_LISTS_WARNING:
            logger.warning(f"⚠ WARNING: {len(chunks)} chunks is close to Cloudflare's 1000 list limit!")

        # Step 4: Delete existing policy (use cached data)
        adblock_rule = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
        if adblock_rule:
            try:
                api_request('DELETE', f"{base_url}/rules/{adblock_rule['id']}")
                cached_rules = [r for r in cached_rules if r['id'] != adblock_rule['id']]
                logger.info(f"✓ Deleted old policy: {policy_name}")
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Could not delete policy {policy_name}: {e}")

        # Step 5: Delete old lists (use cached data)
        lists_to_delete = [lst for lst in cached_lists if lst['name'].startswith(list_prefix)]
        for lst in lists_to_delete:
            try:
                api_request('DELETE', f"{base_url}/lists/{lst['id']}")
                cached_lists = [l for l in cached_lists if l['id'] != lst['id']]
                logger.info(f"✓ Deleted old list: {lst['name']}")
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Could not delete list {lst['name']}: {e}")

        # Step 6: Create new lists
        list_ids = []
        for i, chunk in enumerate(chunks, 1):
            list_name = f"{list_prefix}{i}"
            data_payload = {
                "name": list_name,
                "type": "DOMAIN",
                "description": f"{filter_name} Chunk {i}/{len(chunks)}",
                "items": [{"value": domain} for domain in chunk]
            }
            
            try:
                response = api_request('POST', f"{base_url}/lists", data_payload)
                create_data = check_api_response(response, f"creating list {list_name}")
                list_id = create_data['result']['id']
                list_ids.append(list_id)
                cached_lists.append(create_data['result'])
                logger.info(f"✓ Created list {i}/{len(chunks)}: {list_name} ({len(chunk)} domains)")
                stats["lists_created"] += 1
                time.sleep(API_DELAY)
            except Exception as e:
                logger.error(f"✗ Failed to create list {list_name}: {e}")
                # Clean up already created lists on failure
                logger.info("Cleaning up partially created lists...")
                for created_id in list_ids:
                    try:
                        api_request('DELETE', f"{base_url}/lists/{created_id}")
                        logger.info(f"Cleaned up list {created_id}")
                        time.sleep(API_DELAY)
                    except Exception as cleanup_error:
                        logger.warning(f"Could not cleanup list {created_id}: {cleanup_error}")
                raise

        # Step 7: Create the DNS blocking policy
        if not list_ids:
            logger.warning(f"✗ No lists created. Skipping policy.")
            continue

        expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
        
        # Check expression length
        if len(expression) > 4000:
            logger.warning(f"⚠ Expression length ({len(expression)}) may exceed Cloudflare limits!")
        
        data_payload = {
            "action": "block",
            "description": f"Block domains from {filter_name} ({len(list_ids)} lists, {len(domains)} domains)",
            "enabled": True,
            "filters": ["dns"],
            "name": policy_name,
            "traffic": expression
        }

        response = api_request('POST', f"{base_url}/rules", data_payload)
        create_data = check_api_response(response, f"creating policy {policy_name}")
        cached_rules.append(create_data['result'])
        logger.info(f"✓ Created policy: {policy_name}")
        stats["policies_created"] += 1
        stats["filters_processed"] += 1

    except Exception as e:
        logger.error(f"✗ Failed to process {filter_name}: {e}", exc_info=True)
        stats["errors"].append(filter_name)

# === SUMMARY ===
logger.info(f"\n{'='*60}")
logger.info("SUMMARY")
logger.info(f"{'='*60}")
logger.info(f"Filters processed: {stats['filters_processed']}/{len(blocklists)}")
logger.info(f"Total domains: {stats['total_domains']:,}")
logger.info(f"Lists created: {stats['lists_created']}")
logger.info(f"Policies created: {stats['policies_created']}")
logger.info(f"Total lists in account: {len(cached_lists)}")

if stats['errors']:
    logger.warning(f"\n⚠ Failed filters ({len(stats['errors'])}): {', '.join(stats['errors'])}")
    sys.exit(1)
else:
    logger.info("\n✅ All filters updated successfully!")

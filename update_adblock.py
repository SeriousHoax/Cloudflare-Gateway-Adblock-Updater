# Cloudflare Gateway Adblock Updater
# Author: SeriousHoax
# GitHub: https://github.com/SeriousHoax
# License: MIT

import requests
import aiohttp
import asyncio
import json
import os
import sys
import time
import logging
import re
from typing import Dict, List, Optional
from datetime import datetime

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
API_DELAY = 0.1   # Small delay between requests to avoid rate limiting

# Async configuration
MAX_CONCURRENT_REQUESTS = int(os.environ.get('MAX_CONCURRENT_REQUESTS', '25'))

# Version tracking configuration
VERSION_CACHE_FILE = '.blocklist_versions.json'
FORCE_UPDATE_ALL = os.environ.get('FORCE_UPDATE_ALL', 'false').lower() == 'true'
CHECK_VERSIONS = os.environ.get('CHECK_VERSIONS', 'true').lower() == 'true'

# API base URL
base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

session = requests.Session()
session.headers.update(headers)

# Version tracking functions
def load_version_cache() -> Dict[str, str]:
    """Load cached blocklist versions from file."""
    if os.path.exists(VERSION_CACHE_FILE):
        try:
            with open(VERSION_CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load version cache: {e}")
    return {}

def save_version_cache(versions: Dict[str, str]):
    """Save blocklist versions to cache file."""
    try:
        with open(VERSION_CACHE_FILE, 'w') as f:
            json.dump(versions, f, indent=2)
        logger.info(f"✓ Saved version cache to {VERSION_CACHE_FILE}")
    except Exception as e:
        logger.warning(f"Could not save version cache: {e}")

def fetch_blocklist_version(url: str, backup_url: Optional[str], filter_name: str) -> Optional[str]:
    """Fetch blocklist header to extract version using streaming."""
    for fetch_url in [url, backup_url]:
        if fetch_url is None:
            continue
        try:
            # Use iter_lines to handle gzip/encoding correctly and avoid downloading full file
            with requests.get(fetch_url, timeout=REQUEST_TIMEOUT, stream=True) as response:
                if response.status_code == 200:
                    # Scan first 15 lines for version info (most headers are at the top)
                    for i, line in enumerate(response.iter_lines(decode_unicode=True)):
                        if i > 15:
                            break
                        if not line:
                            continue
                        
                        line = line.strip()
                        if line.startswith('# Version:'):
                            version = line.replace('# Version:', '').strip()
                            logger.info(f"  Found version for {filter_name}: {version}")
                            return version
        except Exception as e:
            logger.warning(f"  Error fetching version from {fetch_url}: {e}")
            continue
    
    logger.warning(f"  No version info found for {filter_name}")
    return None

def should_update_filter(filter_config: Dict, cached_versions: Dict, cached_rules: List[Dict]) -> tuple:
    """
    Check if a filter needs updating based on version comparison AND policy existence.
    Returns: (should_update: bool, current_version: str, reason: str)
    """
    filter_name = filter_config['name']
    policy_name = f"Block {filter_name}"
    
    # Force update if flag set
    if FORCE_UPDATE_ALL:
        return True, None, "FORCE_UPDATE_ALL enabled"
    
    # Skip version check if disabled
    if not CHECK_VERSIONS:
        return True, None, "Version checking disabled"
    
    # Fetch current version from blocklist
    current_version = fetch_blocklist_version(
        filter_config['url'],
        filter_config.get('backup_url'),
        filter_name
    )
    
    if not current_version:
        logger.warning(f"  Could not determine version, will update to be safe")
        return True, None, "Version unknown"
    
    # Compare with cached version
    cached_version = cached_versions.get(filter_name)
    
    if not cached_version:
        logger.info(f"  No cached version found, first run for {filter_name}")
        return True, current_version, "First run"
    
    if current_version != cached_version:
        logger.info(f"  Version changed: {cached_version} → {current_version}")
        return True, current_version, "Version changed"
    
    # Version matches, but verify policy actually exists in Cloudflare
    policy = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
    
    if not policy:
        logger.warning(f"  ⚠ Version matches but policy '{policy_name}' missing in Cloudflare!")
        return True, current_version, "Policy missing (recreating)"
    
    # Check if precedence matches
    target_precedence = filter_config.get('priority')
    current_precedence = policy.get('precedence')
    
    if target_precedence is not None and current_precedence != target_precedence:
        logger.info(f"  ⚠ Precedence mismatch: {current_precedence} (current) ≠ {target_precedence} (target)")
        return True, current_version, f"Precedence mismatch ({current_precedence} -> {target_precedence})"
    
    logger.info(f"  ✅ Version unchanged ({current_version}), skipping update")
    return False, current_version, "Version unchanged"

# Sync API functions (for non-critical operations)
def api_request(method: str, url: str, data: Optional[Dict] = None, 
                retries: int = MAX_RETRIES, backoff_factor: int = BACKOFF_FACTOR, 
                timeout: int = REQUEST_TIMEOUT) -> requests.Response:
    """Make API request with retry logic (sync version)."""
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
            
            items = data.get('result') or []
            all_items.extend(items)
            
            result_info = data.get('result_info') or {}
            total_count = result_info.get('total_count', 0)
            
            if page * result_info.get('per_page', per_page) >= total_count or not items:
                break
            
            page += 1
            time.sleep(API_DELAY)
        
        logger.info(f"Fetched {len(all_items)} items from {endpoint} ({page} page(s))")
        return all_items
    except Exception as e:
        logger.error(f"Pagination failed for {endpoint} at page {page}: {e}", exc_info=True)
        raise



# Async API functions
async def async_api_request(session: aiohttp.ClientSession, method: str, url: str, 
                           data: Optional[Dict] = None) -> Dict:
    """Make async API request with retry logic."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            kwargs = {"timeout": aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)}
            if data:
                kwargs["json"] = data
            
            async with getattr(session, method.lower())(url, **kwargs) as response:
                if response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', BACKOFF_FACTOR * (2 ** (attempt - 1))))
                    logger.warning(f"Rate limited (429). Waiting {retry_after}s...")
                    await asyncio.sleep(retry_after)
                    continue
                
                if response.status >= 500 and attempt < MAX_RETRIES:
                    sleep_time = BACKOFF_FACTOR * (2 ** (attempt - 1))
                    logger.warning(f"Server error {response.status}. Retry {attempt}/{MAX_RETRIES}...")
                    await asyncio.sleep(sleep_time)
                    continue
                
                result = await response.json()
                return {'status': response.status, 'data': result}
                
        except Exception as e:
            if attempt < MAX_RETRIES:
                sleep_time = BACKOFF_FACTOR * (2 ** (attempt - 1))
                await asyncio.sleep(sleep_time)
            else:
                raise Exception(f"All retries exhausted for {method} {url}: {e}")
    
    raise Exception(f"Unexpected error in async_api_request for {method} {url}")

async def async_delete_list(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                            list_id: str, list_name: str) -> bool:
    """Delete a single list asynchronously."""
    async with semaphore:
        try:
            url = f"{base_url}/lists/{list_id}"
            result = await async_api_request(session, 'DELETE', url)
            
            if result['status'] == 200:
                logger.info(f"✓ Deleted list: {list_name}")
                await asyncio.sleep(API_DELAY)
                return True
            else:
                logger.warning(f"Failed to delete {list_name}: {result['status']}")
                return False
        except Exception as e:
            logger.warning(f"Error deleting {list_name}: {e}")
            return False

async def async_create_list(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                           list_name: str, filter_name: str, chunk_num: int, 
                           total_chunks: int, domains: List[str]) -> Optional[str]:
    """Create a single list asynchronously."""
    async with semaphore:
        try:
            data_payload = {
                "name": list_name,
                "type": "DOMAIN",
                "description": f"{filter_name} Chunk {chunk_num}/{total_chunks}",
                "items": [{"value": domain} for domain in domains]
            }
            
            url = f"{base_url}/lists"
            result = await async_api_request(session, 'POST', url, data_payload)
            
            if result['status'] == 200 and result['data'].get('success'):
                list_id = result['data']['result']['id']
                logger.info(f"✓ Created list {chunk_num}/{total_chunks}: {list_name} ({len(domains)} domains)")
                await asyncio.sleep(API_DELAY)
                return list_id
            else:
                logger.error(f"Failed to create {list_name}: {result}")
                return None
        except Exception as e:
            logger.error(f"Error creating {list_name}: {e}")
            return None

async def async_delete_lists_batch(lists_to_delete: List[Dict]) -> int:
    """Delete multiple lists in parallel."""
    if not lists_to_delete:
        return 0
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            async_delete_list(session, semaphore, lst['id'], lst['name'])
            for lst in lists_to_delete
        ]
        results = await asyncio.gather(*tasks)
    
    return sum(1 for r in results if r)

async def async_create_lists_batch(chunks: List[List[str]], filter_name: str, 
                                  list_prefix: str) -> List[str]:
    """Create multiple lists in parallel."""
    if not chunks:
        return []
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            async_create_list(session, semaphore, f"{list_prefix}{i}", 
                            filter_name, i, len(chunks), chunk)
            for i, chunk in enumerate(chunks, 1)
        ]
        results = await asyncio.gather(*tasks)
    
    return [list_id for list_id in results if list_id is not None]

def process_filter_async(filter_config: Dict, cached_lists: List[Dict], 
                        cached_rules: List[Dict]) -> Dict:
    """Process a filter with async list operations."""
    filter_name = filter_config["name"]
    primary_url = filter_config["url"]
    backup_url = filter_config.get("backup_url")
    list_prefix = f"{filter_name.replace(' ', '_')}_List_"
    policy_name = f"Block {filter_name}"

    logger.info(f"{'='*60}")
    logger.info(f"Processing filter (ASYNC): {filter_name}")
    logger.info(f"{'='*60}")

    # Fetch blocklist
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
        except Exception as e:
            logger.warning(f"✗ Error fetching from {url}: {e}")

    if not fetched:
        return {'success': False, 'filter': filter_name}

    # Process domains
    lines = content.splitlines()
    domains = set()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and is_valid_domain(line):
            domains.add(line)

    domains = list(domains)
    logger.info(f"✓ Processed {len(domains):,} unique valid domains")

    if not domains:
        return {'success': False, 'filter': filter_name}

    # Split into chunks
    chunks = list(chunker(domains, CHUNK_SIZE))
    logger.info(f"✓ Split into {len(chunks)} chunk(s)")

    if len(chunks) > MAX_LISTS_WARNING:
        logger.warning(f"⚠ WARNING: {len(chunks)} chunks is close to Cloudflare's 1000 list limit!")

    # Delete existing policy (sync - only one)
    adblock_rule = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
    if adblock_rule:
        try:
            api_request('DELETE', f"{base_url}/rules/{adblock_rule['id']}")
            logger.info(f"✓ Deleted old policy: {policy_name}")
            time.sleep(API_DELAY)
        except Exception as e:
            logger.warning(f"Could not delete policy {policy_name}: {e}")

    # Delete old lists (ASYNC - parallel!)
    lists_to_delete = [lst for lst in cached_lists if lst['name'].startswith(list_prefix)]
    if lists_to_delete:
        logger.info(f"Deleting {len(lists_to_delete)} old lists (async)...")
        start_time = time.time()
        deleted_count = asyncio.run(async_delete_lists_batch(lists_to_delete))
        elapsed = time.time() - start_time
        logger.info(f"✓ Deleted {deleted_count} lists in {elapsed:.1f}s (async)")

    # Create new lists (ASYNC - parallel!)
    logger.info(f"Creating {len(chunks)} new lists (async)...")
    start_time = time.time()
    list_ids = asyncio.run(async_create_lists_batch(chunks, filter_name, list_prefix))
    elapsed = time.time() - start_time
    logger.info(f"✓ Created {len(list_ids)} lists in {elapsed:.1f}s (async)")

    if not list_ids:
        logger.warning(f"✗ No lists created. Skipping policy.")
        return {'success': False, 'filter': filter_name}

    # Create policy with smart priority
    expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
    
    if len(expression) > 4000:
        logger.warning(f"⚠ Expression length ({len(expression)}) may exceed Cloudflare limits!")
    
    # Get priority from filter config
    priority = filter_config.get('priority', 99)
    
    data_payload = {
        "action": "block",
        "description": f"Block domains from {filter_name} ({len(list_ids)} lists, {len(domains)} domains)",
        "enabled": True,
        "filters": ["dns"],
        "name": policy_name,
        "precedence": priority,
        "traffic": expression
    }

    response = api_request('POST', f"{base_url}/rules", data_payload)
    check_api_response(response, f"creating policy {policy_name}")
    logger.info(f"✓ Created policy: {policy_name} (precedence={priority})")

    return {'success': True, 'filter': filter_name, 'domains': len(domains), 'lists': len(list_ids)}

# Blocklists configuration with explicit priorities
# Priority order (lower number = higher priority):
# 1-9999: Reserved for custom policies (Allow Rules, Content Blocking, etc.)
# 10000+: Hagezi filters (ordered by importance)
blocklists: List[Dict[str, str]] = [
    {
        "name": "Hagezi Pro++",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
        "priority": 10000
    },
    {
        "name": "Hagezi-DynDNS",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/dyndns-onlydomains.txt",
        "priority": 20000
    },
    {
        "name": "Xiaomi-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.xiaomi-onlydomains.txt",
        "priority": 30000
    },
    {
        "name": "OppoRealme-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.oppo-realme-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.oppo-realme-onlydomains.txt",
        "priority": 40000
    },
    {
        "name": "Vivo-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.vivo-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.vivo-onlydomains.txt",
        "priority": 50000
    },
    {
        "name": "Samsung-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.samsung-onlydomains.txt",
        "priority": 60000
    },
    {
        "name": "TikTok-native",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok-onlydomains.txt",
        "backup_url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.tiktok-onlydomains.txt",
        "priority": 70000
    }
]

# Execution
logger.info("Starting Cloudflare Gateway Adblock Update...\n")
logger.info(f"Force update all: {'YES' if FORCE_UPDATE_ALL else 'NO'}")
logger.info(f"Check versions: {'ENABLED' if CHECK_VERSIONS else 'DISABLED'}")
logger.info(f"Max concurrent requests: {MAX_CONCURRENT_REQUESTS}\n")

# Load version cache
cached_versions = load_version_cache()
if cached_versions:
    logger.info(f"Loaded {len(cached_versions)} cached versions\n")
else:
    logger.info("No version cache found (first run or cache deleted)\n")

# Cache current state for version checking
logger.info("Caching current rules for policy verification...")
try:
    cached_rules_early = get_all_paginated(f"{base_url}/rules")
    logger.info(f"Cached {len(cached_rules_early)} rules\n")
except Exception as e:
    logger.warning(f"Could not cache rules: {e}. Continuing without policy verification...")
    cached_rules_early = []

# Check which filters need updating
filters_to_update = []
updated_versions = {}

logger.info("Checking blocklist versions...\n")
for bl in blocklists:
    filter_name = bl['name']
    should_update, current_version, reason = should_update_filter(bl, cached_versions, cached_rules_early)
    
    if should_update:
        logger.info(f"✅ {filter_name}: WILL UPDATE ({reason})")
        filters_to_update.append(bl)
        if current_version:
            updated_versions[filter_name] = current_version
    else:
        logger.info(f"⏭️  {filter_name}: SKIP ({reason})")
        if filter_name in cached_versions:
            updated_versions[filter_name] = cached_versions[filter_name]
        if current_version:
            updated_versions[filter_name] = current_version

logger.info(f"\n{'='*60}")
logger.info(f"Filters to update: {len(filters_to_update)}/{len(blocklists)}")
logger.info(f"{'='*60}\n")

if not filters_to_update:
    logger.info("🎉 All filters are up to date! No updates needed.")
    logger.info("\n✅ Script completed successfully!")
    sys.exit(0)

# Cache current state
logger.info("Caching current rules and lists...")
try:
    cached_rules = get_all_paginated(f"{base_url}/rules")
    cached_lists = get_all_paginated(f"{base_url}/lists")
    logger.info(f"Cached {len(cached_rules)} rules and {len(cached_lists)} lists\n")
except Exception as e:
    logger.error(f"Failed to cache rules/lists: {e}", exc_info=True)
    sys.exit(1)

# Process filters with async
stats = {
    "filters_processed": 0,
    "total_domains": 0,
    "lists_created": 0,
    "policies_created": 0,
    "errors": []
}

script_start = time.time()

for bl in filters_to_update:
    try:
        filter_start = time.time()
        result = process_filter_async(bl, cached_lists, cached_rules)
        filter_elapsed = time.time() - filter_start
        
        if result['success']:
            stats["filters_processed"] += 1
            stats["total_domains"] += result.get('domains', 0)
            stats["lists_created"] += result.get('lists', 0)
            stats["policies_created"] += 1
            
            logger.info(f"Filter completed in {filter_elapsed:.1f}s")
            
            # Refresh cache
            cached_rules = get_all_paginated(f"{base_url}/rules")
            cached_lists = get_all_paginated(f"{base_url}/lists")
        else:
            stats["errors"].append(bl['name'])
            
    except Exception as e:
        logger.error(f"✗ Failed to process {bl['name']}: {e}", exc_info=True)
        stats["errors"].append(bl['name'])

script_elapsed = time.time() - script_start

# Save version cache
save_version_cache(updated_versions)

# Summary
logger.info(f"\n{'='*60}")
logger.info("SUMMARY")
logger.info(f"{'='*60}")
logger.info(f"Filters checked: {len(blocklists)}")
logger.info(f"Filters updated: {stats['filters_processed']}/{len(filters_to_update)}")
logger.info(f"Filters skipped: {len(blocklists) - len(filters_to_update)}")
logger.info(f"Total domains: {stats['total_domains']:,}")
logger.info(f"Lists created: {stats['lists_created']}")
logger.info(f"Policies created: {stats['policies_created']}")
logger.info(f"Total lists in account: {len(cached_lists)}")
logger.info(f"\n⏱️  Total script execution time: {script_elapsed:.1f}s")

if stats['errors']:
    logger.warning(f"\n⚠ Failed filters ({len(stats['errors'])}): {', '.join(stats['errors'])}")
    sys.exit(1)
else:
    logger.info("\n✅ All filters updated successfully!")

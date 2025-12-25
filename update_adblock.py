# Cloudflare Gateway Adblock Updater
# Author: SeriousHoax
# GitHub: https://github.com/SeriousHoax
# License: MIT

import requests
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

def extract_version_from_content(content: str, filter_name: str) -> Optional[str]:
    """
    Extract version from blocklist header.
    Looks for lines like: # Version: 2025.1222.2237.20
    Also accepts: # Last modified: 22 Dec 2025 22:37 UTC
    """
    lines = content.splitlines()[:20]  # Only check first 20 lines
    
    # First try to find Version line
    for line in lines:
        line = line.strip()
        if line.startswith('# Version:'):
            version = line.replace('# Version:', '').strip()
            logger.info(f"  Found version for {filter_name}: {version}")
            return version
    
    # Fallback: use Last modified as version
    for line in lines:
        line = line.strip()
        if line.startswith('# Last modified:'):
            modified = line.replace('# Last modified:', '').strip()
            logger.info(f"  Found last modified for {filter_name}: {modified}")
            return modified
    
    logger.warning(f"  No version info found for {filter_name}")
    return None

def fetch_blocklist_version(url: str, backup_url: Optional[str], filter_name: str) -> Optional[str]:
    """
    Fetch just the header of a blocklist to extract version.
    Much faster than downloading the entire file.
    """
    for fetch_url in [url, backup_url]:
        if fetch_url is None:
            continue
        try:
            # Use stream=True to only fetch first few KB
            response = requests.get(fetch_url, timeout=REQUEST_TIMEOUT, stream=True)
            if response.status_code == 200:
                # Read only first 2KB (enough for headers)
                content = response.raw.read(2048).decode('utf-8', errors='ignore')
                response.close()
                
                version = extract_version_from_content(content, filter_name)
                if version:
                    return version
                
                # If no version found, fallback to fetching full content
                logger.info(f"  No version in header, fetching full content...")
                response = requests.get(fetch_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    return extract_version_from_content(response.text, filter_name)
        except Exception as e:
            logger.warning(f"  Error fetching version from {fetch_url}: {e}")
            continue
    
    return None

def should_update_filter(filter_config: Dict, cached_versions: Dict) -> tuple:
    """
    Check if a filter needs updating based on version comparison.
    Returns: (should_update: bool, current_version: str, reason: str)
    """
    filter_name = filter_config['name']
    
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
    
    logger.info(f"  ✅ Version unchanged ({current_version}), skipping update")
    return False, current_version, "Version unchanged"

# Core API functions
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

def process_filter(filter_config: Dict, cached_lists: List[Dict], cached_rules: List[Dict]) -> Dict:
    """
    Process a single blocklist with full recreate
    This is called only when version changes detected.
    """
    filter_name = filter_config["name"]
    primary_url = filter_config["url"]
    backup_url = filter_config.get("backup_url")
    list_prefix = f"{filter_name.replace(' ', '_')}_List_"
    policy_name = f"Block {filter_name}"

    logger.info(f"{'='*60}")
    logger.info(f"Processing filter: {filter_name}")
    logger.info(f"{'='*60}")

    # Step 1: Fetch the blocklist
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
        return {'success': False, 'filter': filter_name}

    # Step 2: Process domains
    lines = content.splitlines()
    domains = set()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and is_valid_domain(line):
            domains.add(line)

    domains = list(domains)
    logger.info(f"✓ Processed {len(domains):,} unique valid domains")

    if not domains:
        logger.warning(f"✗ No valid domains found. Skipping.")
        return {'success': False, 'filter': filter_name}

    # Step 3: Split into chunks
    chunks = list(chunker(domains, CHUNK_SIZE))
    logger.info(f"✓ Split into {len(chunks)} chunk(s)")

    if len(chunks) > MAX_LISTS_WARNING:
        logger.warning(f"⚠ WARNING: {len(chunks)} chunks is close to Cloudflare's 1000 list limit!")

    # Step 4: Delete existing policy
    adblock_rule = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
    if adblock_rule:
        try:
            api_request('DELETE', f"{base_url}/rules/{adblock_rule['id']}")
            logger.info(f"✓ Deleted old policy: {policy_name}")
            time.sleep(API_DELAY)
        except Exception as e:
            logger.warning(f"Could not delete policy {policy_name}: {e}")

    # Step 5: Delete old lists
    lists_to_delete = [lst for lst in cached_lists if lst['name'].startswith(list_prefix)]
    for lst in lists_to_delete:
        try:
            api_request('DELETE', f"{base_url}/lists/{lst['id']}")
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
            logger.info(f"✓ Created list {i}/{len(chunks)}: {list_name} ({len(chunk)} domains)")
            time.sleep(API_DELAY)
        except Exception as e:
            logger.error(f"✗ Failed to create list {list_name}: {e}")
            # Clean up on failure
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
        return {'success': False, 'filter': filter_name}

    expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
    
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
    check_api_response(response, f"creating policy {policy_name}")
    logger.info(f"✓ Created policy: {policy_name}")

    return {'success': True, 'filter': filter_name, 'domains': len(domains), 'lists': len(list_ids)}

# Blocklists configuration
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

# Execution
logger.info("Starting Cloudflare Gateway Adblock Update with VERSION TRACKING...\n")
logger.info(f"Force update all: {'YES' if FORCE_UPDATE_ALL else 'NO'}")
logger.info(f"Check versions: {'ENABLED' if CHECK_VERSIONS else 'DISABLED'}\n")

# Load version cache
cached_versions = load_version_cache()
if cached_versions:
    logger.info(f"Loaded {len(cached_versions)} cached versions\n")
else:
    logger.info("No version cache found (first run or cache deleted)\n")

# Check which filters need updating
filters_to_update = []
updated_versions = {}

logger.info("Checking blocklist versions...\n")
for bl in blocklists:
    filter_name = bl['name']
    should_update, current_version, reason = should_update_filter(bl, cached_versions)
    
    if should_update:
        logger.info(f"✅ {filter_name}: WILL UPDATE ({reason})")
        filters_to_update.append(bl)
        if current_version:
            updated_versions[filter_name] = current_version
    else:
        logger.info(f"⏭️  {filter_name}: SKIP ({reason})")
        # Keep existing version in cache
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

# Cache current state (only fetch if we have filters to update)
logger.info("Caching current rules and lists...")
try:
    cached_rules = get_all_paginated(f"{base_url}/rules")
    cached_lists = get_all_paginated(f"{base_url}/lists")
    logger.info(f"Cached {len(cached_rules)} rules and {len(cached_lists)} lists\n")
except Exception as e:
    logger.error(f"Failed to cache rules/lists: {e}", exc_info=True)
    sys.exit(1)

# Process filters that need updating
stats = {
    "filters_processed": 0,
    "total_domains": 0,
    "lists_created": 0,
    "policies_created": 0,
    "errors": []
}

for bl in filters_to_update:
    try:
        result = process_filter(bl, cached_lists, cached_rules)
        
        if result['success']:
            stats["filters_processed"] += 1
            stats["total_domains"] += result.get('domains', 0)
            stats["lists_created"] += result.get('lists', 0)
            stats["policies_created"] += 1
            
            # Refresh cache after each filter
            cached_rules = get_all_paginated(f"{base_url}/rules")
            cached_lists = get_all_paginated(f"{base_url}/lists")
        else:
            stats["errors"].append(bl['name'])
            
    except Exception as e:
        logger.error(f"✗ Failed to process {bl['name']}: {e}", exc_info=True)
        stats["errors"].append(bl['name'])

# Save updated version cache
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

if stats['errors']:
    logger.warning(f"\n⚠ Failed filters ({len(stats['errors'])}): {', '.join(stats['errors'])}")
    sys.exit(1)
else:
    logger.info("\n✅ All filters updated successfully!")

import requests
import json
import os
import sys
import time
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Get env vars from GitHub secrets
api_token = os.environ.get('CLOUDFLARE_API_TOKEN')
account_id = os.environ.get('CLOUDFLARE_ACCOUNT_ID')
if not api_token or not account_id:
    logger.error("Missing API token or account ID.")
    sys.exit(1)

# Configuration constants
CHUNK_SIZE = 1000 # Cloudflare limit per list
MAX_LISTS_WARNING = 900 # Warning threshold
API_DELAY = 0.3 # Delay between API calls (seconds)
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))
MAX_RETRIES = 3
BACKOFF_FACTOR = 5

# API base URL
base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"

# Setup session with connection pooling
session = requests.Session()
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=Retry(total=0) # We handle retries manually
)
session.mount('https://', adapter)
session.headers.update({
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
})

# Pre-compile regex for performance
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')

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
   
    raise last_exception if last_exception else Exception("Unknown error in api_request")

def check_api_response(response: requests.Response, action: str) -> Dict:
    """Validate API response and return JSON data."""
    if response.status_code != 200:
        error_msg = f"Error {action}: {response.status_code} - {response.text}"
        logger.error(error_msg)
        raise Exception(error_msg)
   
    data = response.json()
    if not data.get('success', False):
        error_msg = f"API success false during {action}: {json.dumps(data)}"
        logger.error(error_msg)
        raise Exception(error_msg)
       
    return data

def is_valid_domain(domain: str) -> bool:
    """Validate domain format and length."""
    return bool(DOMAIN_PATTERN.match(domain.lower())) and len(domain) <= 253

def chunker(seq: List[str], size: int):
    """Split list into chunks of specified size."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]

def get_all_paginated(endpoint: str, per_page: int = 100) -> List[Dict]:
    """Fetch all items from paginated endpoint."""
    all_items = []
    page = 1
   
    while True:
        url = f"{endpoint}?per_page={per_page}&page={page}"
        response = api_request('GET', url)
        data = check_api_response(response, f"getting {endpoint} page {page}")
        
        # Safely get 'result' as empty list if missing or None
        items = data.get('result') or []
        all_items.extend(items)
       
        # Safely get 'result_info' as empty dict if missing or None
        result_info = data.get('result_info') or {}
        
        # Use safe defaults in the check
        current_total = page * result_info.get('per_page', per_page)
        total_count = result_info.get('total_count', 0)
        if current_total >= total_count:
            break
        page += 1
       
    logger.info(f"Fetched {len(all_items)} items from {endpoint}.")
    return all_items

def fetch_blocklist(url: str, backup_url: Optional[str], name: str, timeout: int) -> Optional[str]:
    """Fetch blocklist content from primary or backup URL."""
    for source_url in [url, backup_url]:
        if source_url is None:
            continue
        try:
            response = requests.get(source_url, timeout=timeout)
            if response.status_code == 200:
                logger.info(f"Successfully fetched {name} from {source_url}")
                return response.text
            else:
                logger.warning(f"Failed to fetch {name} from {source_url}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching {name} from {source_url}: {e}")
   
    return None

def process_blocklist_content(content: str) -> Set[str]:
    """Process blocklist content and extract valid domains."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and is_valid_domain(line):
            domains.add(line)
    return domains

def cleanup_filter_resources(filter_name: str, list_prefix: str, policy_name: str,
                            cached_rules: List[Dict], cached_lists: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Clean up existing resources for a filter."""
    # Delete existing policy
    adblock_rule = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
    if adblock_rule:
        rule_id = adblock_rule['id']
        try:
            delete_response = api_request('DELETE', f"{base_url}/rules/{rule_id}")
            check_api_response(delete_response, f"deleting policy for {filter_name}")
            logger.info(f"Deleted existing policy: {policy_name}")
            cached_rules = [r for r in cached_rules if r['id'] != rule_id]
            time.sleep(API_DELAY)
        except Exception as e:
            logger.warning(f"Failed to delete policy {policy_name}: {e}")
    # Delete old lists
    lists_to_delete = [lst for lst in cached_lists if lst['name'].startswith(list_prefix)]
    for lst in lists_to_delete:
        try:
            delete_response = api_request('DELETE', f"{base_url}/lists/{lst['id']}")
            check_api_response(delete_response, f"deleting list {lst['name']} for {filter_name}")
            logger.info(f"Deleted old list: {lst['name']}")
            cached_lists = [l for l in cached_lists if l['id'] != lst['id']]
            time.sleep(API_DELAY)
        except Exception as e:
            logger.warning(f"Failed to delete list {lst['name']}: {e}")
   
    return cached_rules, cached_lists

def create_lists_for_filter(filter_name: str, list_prefix: str, chunks: List[List[str]],
                           cached_lists: List[Dict]) -> List[str]:
    """Create Gateway lists for filter chunks."""
    list_ids = []
   
    for i, chunk in enumerate(chunks, 1):
        list_name = f"{list_prefix}{i}"
        data_payload = {
            "name": list_name,
            "type": "DOMAIN",
            "description": f"{filter_name} Adblock Chunk {i}/{len(chunks)}",
            "items": [{"value": domain} for domain in chunk]
        }
       
        try:
            response = api_request('POST', f"{base_url}/lists", data_payload)
            create_data = check_api_response(response, f"creating list {list_name} for {filter_name}")
            list_id = create_data['result']['id']
            list_ids.append(list_id)
            cached_lists.append(create_data['result'])
            logger.info(f"Created list: {list_name} with {len(chunk)} items (ID: {list_id}) [{i}/{len(chunks)}]")
            time.sleep(API_DELAY) # Rate limiting
        except Exception as e:
            logger.error(f"Failed to create list {list_name}: {e}")
            # Clean up already created lists on failure
            for created_id in list_ids:
                try:
                    api_request('DELETE', f"{base_url}/lists/{created_id}")
                    logger.info(f"Cleaned up list {created_id} after failure")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup list {created_id}: {cleanup_error}")
            raise
   
    return list_ids

# Define blocklists
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

# Derive cleanup names from blocklists
old_policy_names = [f"Block {bl['name']}" for bl in blocklists]
old_prefixes = [f"{bl['name'].replace(' ', '_')}_List_" for bl in blocklists]

logger.info("Starting Cloudflare Gateway Adblock Update...")
stats = {
    "filters_processed": 0,
    "total_domains": 0,
    "lists_created": 0,
    "policies_created": 0,
    "errors": []
}

# Global cleanup (non-fatal, for orphans from previous failed runs)
try:
    logger.info("\nPerforming global cleanup...")
    all_rules = get_all_paginated(f"{base_url}/rules")
    all_lists = get_all_paginated(f"{base_url}/lists")
   
    for rule in all_rules:
        if rule['name'] in old_policy_names:
            try:
                api_request('DELETE', f"{base_url}/rules/{rule['id']}")
                logger.info(f"Cleaned up orphan policy: {rule['name']}")
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Failed to delete orphan policy {rule['name']}: {e}")
   
    for lst in all_lists:
        if any(lst['name'].startswith(prefix) for prefix in old_prefixes):
            try:
                api_request('DELETE', f"{base_url}/lists/{lst['id']}")
                logger.info(f"Cleaned up orphan list: {lst['name']}")
                time.sleep(API_DELAY)
            except Exception as e:
                logger.warning(f"Failed to delete orphan list {lst['name']}: {e}")
except Exception as e:
    logger.warning(f"Global cleanup failed: {e}. Continuing...")

# Cache initial rules/lists (Refetch after cleanup to ensure cache is accurate)
cached_rules = get_all_paginated(f"{base_url}/rules")
cached_lists = get_all_paginated(f"{base_url}/lists")

# Track total lists across all filters
total_lists_count = len(cached_lists)

# Process each blocklist
for bl in blocklists:
    filter_name = bl["name"]
    primary_url = bl["url"]
    backup_url = bl.get("backup_url")
    list_prefix = f"{filter_name.replace(' ', '_')}_List_"
    policy_name = f"Block {filter_name}"
    logger.info(f"\n{'='*60}")
    logger.info(f"Processing filter: {filter_name}")
    logger.info(f"{'='*60}")
    try:
        # Fetch the blocklist
        content = fetch_blocklist(primary_url, backup_url, filter_name, REQUEST_TIMEOUT)
        if not content:
            logger.error(f"Failed to fetch blocklist for {filter_name} from all sources. Skipping.")
            stats["errors"].append(filter_name)
            continue
        # Process the list
        domains = process_blocklist_content(content)
        domains = list(domains)
        logger.info(f"Fetched and processed {len(domains)} unique domains for {filter_name}.")
        stats["total_domains"] += len(domains)
        if not domains:
            logger.info(f"No domains for {filter_name}. Skipping.")
            continue
        # Split into chunks
        chunks = list(chunker(domains, CHUNK_SIZE))
        logger.info(f"Split {filter_name} into {len(chunks)} chunks.")
        # Check list limits
        if len(chunks) > MAX_LISTS_WARNING:
            logger.warning(f"WARNING: {filter_name} has {len(chunks)} chunks, approaching Cloudflare's limit.")
       
        if total_lists_count + len(chunks) > MAX_LISTS_WARNING:
            logger.warning(f"WARNING: Total lists ({total_lists_count + len(chunks)}) approaching account limit!")
        # Clean up existing resources for this filter
        cached_rules, cached_lists = cleanup_filter_resources(
            filter_name, list_prefix, policy_name, cached_rules, cached_lists
        )
        # Create new lists
        list_ids = create_lists_for_filter(filter_name, list_prefix, chunks, cached_lists)
        stats["lists_created"] += len(list_ids)
        total_lists_count += len(list_ids)
        # Create the DNS blocking policy
        if not list_ids:
            logger.info(f"No lists created for {filter_name}. Skipping policy.")
            continue
        expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
       
        # Check expression length (Cloudflare has limits)
        if len(expression) > 4000:
            logger.warning(f"WARNING: Expression length ({len(expression)}) may exceed Cloudflare limits!")
        data_payload = {
            "action": "block",
            "description": f"Block using {filter_name} list ({len(list_ids)} lists, {len(domains)} domains)",
            "enabled": True,
            "filters": ["dns"],
            "name": policy_name,
            "traffic": expression
        }
        response = api_request('POST', f"{base_url}/rules", data_payload)
        create_data = check_api_response(response, f"creating policy for {filter_name}")
        logger.info(f"Created new policy: {policy_name}")
        stats["policies_created"] += 1
        cached_rules.append(create_data['result'])
        stats["filters_processed"] += 1
    except Exception as e:
        logger.error(f"Failed to process {filter_name}: {e}", exc_info=True)
        stats["errors"].append(filter_name)

# Final summary
logger.info(f"\n{'='*60}")
logger.info(f"SUMMARY")
logger.info(f"{'='*60}")
logger.info(f"Filters processed: {stats['filters_processed']}/{len(blocklists)}")
logger.info(f"Total domains: {stats['total_domains']:,}")
logger.info(f"Lists created: {stats['lists_created']}")
logger.info(f"Policies created: {stats['policies_created']}")
logger.info(f"Total lists in account: {total_lists_count}")
if stats['errors']:
    logger.warning(f"Failed filters: {', '.join(stats['errors'])}")
    sys.exit(1)
else:
    logger.info("✅ All filters updated successfully.")

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
VERSION_CACHE_FILE = 'blocklist_versions.json'
Fresh_Start = os.environ.get('FRESH_START', 'false').lower() == 'true'
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
    
    # Fresh start if flag set
    if Fresh_Start:
        return True, None, "Fresh_Start enabled"
    
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
        logger.info(f"  ✅ Version changed: {cached_version} → {current_version}")
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
    
    logger.info(f"  ⏭️ Version unchanged ({current_version}), skipping update")
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
    pattern = r'^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$'
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
        
        safe_endpoint = endpoint.replace(account_id, '[HIDDEN]')
        logger.info(f"Fetched {len(all_items)} items from {safe_endpoint} ({page} page(s))")
        return all_items
    except Exception as e:
        logger.error(f"Pagination failed for {endpoint} at page {page}: {e}", exc_info=True)
        raise

def get_location_id_by_name(location_name: str) -> Optional[str]:
    """Get location ID (UUID) by location name."""
    try:
        all_locations = get_all_paginated(f"{base_url}/locations")
        for location in all_locations:
            if location.get('name') == location_name:
                return location.get('id')
        logger.warning(f"Location '{location_name}' not found")
        return None
    except Exception as e:
        logger.error(f"Failed to fetch locations: {e}")
        return None



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

async def async_get_list_items(session: aiohttp.ClientSession, list_id: str) -> List[str]:
    """Fetch all items from a list."""
    all_items = []
    page = 1
    per_page = 1000  # Max per page for this endpoint can be higher
    
    while True:
        url = f"{base_url}/lists/{list_id}/items?per_page={per_page}&page={page}"
        result = await async_api_request(session, 'GET', url)
        
        if result['status'] != 200:
            logger.warning(f"Failed to get items for list {list_id}: {result['status']}")
            break
            
        data = result['data']
        items = data.get('result') or []
        all_items.extend(item['value'] for item in items)
        
        result_info = data.get('result_info') or {}
        total_count = result_info.get('total_count', 0)
        
        if page * per_page >= total_count or not items:
            break
            
        page += 1
        await asyncio.sleep(API_DELAY)
        
    return all_items

async def async_patch_list(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                          list_id: str, list_name: str, remove: List[str], append: List[str]) -> bool:
    """Patch a list by removing and/or appending items."""
    if not remove and not append:
        return True
        
    async with semaphore:
        try:
            payload = {}
            if remove:
                payload['remove'] = remove
            if append:
                payload['append'] = [{'value': domain} for domain in append]
                
            url = f"{base_url}/lists/{list_id}"
            result = await async_api_request(session, 'PATCH', url, payload)
            
            if result['status'] == 200:
                logger.info(f"  ✓ Patched {list_name}: -{len(remove)} / +{len(append)}")
                await asyncio.sleep(API_DELAY)
                return True
            else:
                logger.warning(f"  ✗ Failed to patch {list_name}: {result['status']}")
                return False
        except Exception as e:
            logger.error(f"  ✗ Error patching {list_name}: {e}")
            return False

async def async_update_policy(session: aiohttp.ClientSession, policy_id: str, 
                             policy_data: Dict) -> bool:
    """Update an existing policy."""
    try:
        url = f"{base_url}/rules/{policy_id}"
        result = await async_api_request(session, 'PUT', url, policy_data)
        
        if result['status'] == 200:
            logger.info(f"✓ Updated policy: {policy_data['name']}")
            return True
        else:
            logger.error(f"Failed to update policy {policy_data['name']}: {result}")
            return False
    except Exception as e:
        logger.error(f"Error updating policy {policy_data['name']}: {e}")
        return False

def update_policy_for_filter(filter_config: Dict, final_list_ids: List[str], 
                             target_domain_count: int, cached_rules: List[Dict]) -> bool:
    """Update or create the policy for a filter."""
    filter_name = filter_config["name"]
    policy_name = f"Block {filter_name}"

    if not final_list_ids:
        logger.warning(f"Total list count is 0! Skipping policy update.")
        return False

    # Build traffic expression
    location_names = filter_config.get('location_ids', [])
    if location_names:
        location_uuids = []
        for loc_name in location_names:
            loc_id = get_location_id_by_name(loc_name)
            if loc_id:
                location_uuids.append(loc_id)
        
        if not location_uuids:
             return False

        location_set = " ".join([f'"{uuid}"' for uuid in location_uuids])
        location_condition = f'dns.location in {{{location_set}}}'
        expression = " or ".join([f"(any(dns.domains[*] in ${lid}) and {location_condition})" for lid in final_list_ids])
    else:
        expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in final_list_ids])

    priority = filter_config.get('priority', 99)
    policy_payload = {
        "action": "block",
        "description": f"Block domains from {filter_name} ({len(final_list_ids)} lists, {target_domain_count} domains)",
        "enabled": True,
        "filters": ["dns"],
        "name": policy_name,
        "precedence": priority,
        "traffic": expression
    }

    # Check if policy exists to determine POST or PUT
    existing_policy = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
    
    if existing_policy:
        logger.info(f"Updating existing policy '{policy_name}'...")
        async def run_update():
             # Create a new session for this operation
            async with aiohttp.ClientSession(headers=headers) as session:
                return await async_update_policy(session, existing_policy['id'], policy_payload)
        return asyncio.run(run_update())
    else:
        logger.info(f"Creating new policy '{policy_name}'...")
        # Fallback to sync request for creation as we didn't make an async helper for simple POST rule
        try:
            response = api_request('POST', f"{base_url}/rules", policy_payload)
            check_api_response(response, f"creating policy {policy_name}")
            return True
        except:
            return False

def process_filter_async(filter_config: Dict, cached_lists: List[Dict], 
                        cached_rules: List[Dict]) -> Dict:
    """Process a filter with diff-based updates."""
    filter_name = filter_config["name"]
    primary_url = filter_config["url"]
    backup_url = filter_config.get("backup_url")
    list_prefix = f"{filter_name.replace(' ', '_')}_List_"
    policy_name = f"Block {filter_name}"

    logger.info(f"{'='*60}")
    logger.info(f"Processing filter (DIFF-SYNC): {filter_name}")
    logger.info(f"{'='*60}")

    # Fetch blocklist source
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

    # Parse domains from source
    lines = content.splitlines()
    target_domains = set()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and is_valid_domain(line):
            target_domains.add(line)

    logger.info(f"✓ Target domains: {len(target_domains):,}")

    if not target_domains and not Fresh_Start: # Safety check, unless forced
        logger.warning(f"✗ No domains found in source! Aborting to prevent emptying lists.")
        return {'success': False, 'filter': filter_name}

    # Identify existing lists for this filter
    existing_lists = [lst for lst in cached_lists if lst['name'].startswith(list_prefix)]
    # Sort by chunk number
    try:
        existing_lists.sort(key=lambda x: int(x['name'].replace(list_prefix, '')) if x['name'].replace(list_prefix, '').isdigit() else 999999)
    except:
        pass # Fallback if naming is weird
        
    logger.info(f"✓ Found {len(existing_lists)} existing lists for {filter_name}")

    # Process Lists (Diff vs Full Cleanup)
    if Fresh_Start:
        logger.info(f"‼ FULL CLEANUP MODE: Deleting everything first for {filter_name}")

        # Delete Policy if exists
        # We need to delete the policy first so we can delete the lists it uses
        existing_policy = next((rule for rule in cached_rules if rule['name'] == policy_name), None)
        if existing_policy:
            logger.info(f"Deleting policy '{policy_name}'...")
            try:
                # Sync request is fine here for single operation
                response = api_request('DELETE', f"{base_url}/rules/{existing_policy['id']}")
                check_api_response(response, f"deleting policy {policy_name}")
                # Remove from cached_rules so helper knows to create new later
                cached_rules = [r for r in cached_rules if r['id'] != existing_policy['id']]
            except Exception as e:
                logger.error(f"Failed to delete policy {policy_name}: {e}")
                # We attempt to continue, but if policy deletion failed, list deletion might fail too (in use)

        # Delete ALL existing lists
        if existing_lists:
            logger.info(f"Deleting {len(existing_lists)} old lists...")
            asyncio.run(async_delete_lists_batch(existing_lists))

        # Create New Lists
        domain_list = list(target_domains)
        chunks = list(chunker(domain_list, CHUNK_SIZE))
        
        async def create_all_new_chunks_cleanup():
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            async with aiohttp.ClientSession(headers=headers) as session:
                tasks = []
                for i, chunk in enumerate(chunks):
                    # In destructive mode, we can start from 1 cleanly
                    chunk_num = i + 1
                    list_name = f"{list_prefix}{chunk_num}"
                    tasks.append(async_create_list(session, semaphore, list_name, 
                                                 filter_name, chunk_num, len(chunks), chunk))
                return await asyncio.gather(*tasks)

        created_ids = asyncio.run(create_all_new_chunks_cleanup())
        new_list_ids = [lid for lid in created_ids if lid]
        
        # Create Policy
        policy_success = update_policy_for_filter(filter_config, new_list_ids, len(target_domains), cached_rules)

        if not policy_success:
            return {'success': False, 'filter': filter_name}

        return {'success': True, 'filter': filter_name, 'domains': len(target_domains), 'lists': len(new_list_ids)}

    # Fetch current Cloudflare content (ASYNC)
    remote_domain_to_list_map = {} # domain -> list_id
    list_capacities = {} # list_id -> current_count

    async def fetch_all_current_content():
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = []
            for lst in existing_lists:
                tasks.append(async_get_list_items(session, lst['id']))
            
            results = await asyncio.gather(*tasks)
            
            for i, domains in enumerate(results):
                lst = existing_lists[i]
                list_capacities[lst['id']] = len(domains)
                for d in domains:
                    remote_domain_to_list_map[d] = lst['id']
    
    if existing_lists:
        logger.info("Fetching current list contents from Cloudflare...")
        asyncio.run(fetch_all_current_content())

    # Calculate Diff
    current_remote_domains = set(remote_domain_to_list_map.keys())
    
    # Domains to remove: in Gateway but not in Target
    to_remove = current_remote_domains - target_domains
    
    # Domains to add: in Target but not in Gateway
    to_add = list(target_domains - current_remote_domains)
    
    logger.info(f"Diff analysis:")
    logger.info(f"  - To remove: {len(to_remove)}")
    logger.info(f"  - To add:    {len(to_add)}")
    logger.info(f"  - Unchanged: {len(target_domains) - len(to_add)}")

    # Apply Patches (ASYNC)
    
    # Group removals by list
    removals_by_list = {} # list_id -> [domains]
    for domain in to_remove:
        list_id = remote_domain_to_list_map[domain]
        if list_id not in removals_by_list:
            removals_by_list[list_id] = []
        removals_by_list[list_id].append(domain)

    patches = {} # list_id -> {'remove': [], 'append': []}

    # Plan removals
    for list_id, domains in removals_by_list.items():
        if list_id not in patches:
            patches[list_id] = {'remove': [], 'append': []}
        patches[list_id]['remove'] = domains
        # Update capacity locally
        list_capacities[list_id] -= len(domains)

    # Plan additions (fill holes + use space)
    for lst in existing_lists:
        list_id = lst['id']
        current_cap = list_capacities.get(list_id, 0)
        space = CHUNK_SIZE - current_cap
        
        if space > 0 and to_add:
            # Take as much as fits
            chunk_add = to_add[:space]
            to_add = to_add[space:]
            
            if list_id not in patches:
                patches[list_id] = {'remove': [], 'append': []}
            patches[list_id]['append'] = chunk_add
            list_capacities[list_id] += len(chunk_add)

    # Execute patches
    async def execute_patches():
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = []
            for list_id, patch_data in patches.items():
                list_name = next((l['name'] for l in existing_lists if l['id'] == list_id), list_id)
                tasks.append(async_patch_list(session, semaphore, list_id, list_name, 
                                            patch_data['remove'], patch_data['append']))
            await asyncio.gather(*tasks)

    if patches:
        logger.info(f"Executing {len(patches)} patches...")
        asyncio.run(execute_patches())
    else:
        logger.info("No patches needed for existing lists.")

    # Create New Lists for remaining additions
    new_list_ids = []
    if to_add:
        logger.info(f"Creating new lists for {len(to_add)} remaining domains...")
        chunks = list(chunker(to_add, CHUNK_SIZE))
        
        # Determine next chunk number
        current_max_chunk = 0
        for lst in existing_lists:
            try:
                num = int(lst['name'].replace(list_prefix, ''))
                current_max_chunk = max(current_max_chunk, num)
            except:
                pass
        
        # Determine start index for new chunks to continue numbering from existing lists
        # Example: If List_5 exists, new chunks start at List_6
        # We manually loop here to ensure correct numbering avoids conflicts
        
        async def create_new_chunks():
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            async with aiohttp.ClientSession(headers=headers) as session:
                tasks = []
                for i, chunk in enumerate(chunks):
                    chunk_num = current_max_chunk + 1 + i
                    list_name = f"{list_prefix}{chunk_num}"
                    tasks.append(async_create_list(session, semaphore, list_name, 
                                                 filter_name, chunk_num, len(chunks)+current_max_chunk, chunk))
                return await asyncio.gather(*tasks)

        created_ids = asyncio.run(create_new_chunks())
        new_list_ids = [lid for lid in created_ids if lid]

    # Cleanup empty lists
    # If patches caused a list to become empty (and no appends filled it), we should delete it
    # Check capacities
    lists_to_delete = []
    final_list_ids = []
    
    for lst in existing_lists:
        if list_capacities.get(lst['id'], 0) == 0:
            lists_to_delete.append(lst)
        else:
            final_list_ids.append(lst['id'])
            
    if lists_to_delete:
        logger.info(f"Deleting {len(lists_to_delete)} empty lists...")
        asyncio.run(async_delete_lists_batch(lists_to_delete))
        
    final_list_ids.extend(new_list_ids)

    # Update/Create Policy
    policy_success = update_policy_for_filter(filter_config, final_list_ids, len(target_domains), cached_rules)

    if not policy_success:
        return {'success': False, 'filter': filter_name}

    return {'success': True, 'filter': filter_name, 'domains': len(target_domains), 'lists': len(final_list_ids)}

# Blocklists configuration with explicit priorities
# Priority order (lower number = higher priority):
# 1-9999: Reserved for custom policies (Allow Rules, Content Blocking, etc.)
# 10000+: Hagezi filters (ordered by importance)
blocklists: List[Dict[str, str]] = [
    {
        "name": "Hagezi Pro++",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "priority": 10000
    },
    {
        "name": "Hagezi-DynDNS",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/dyndns-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "priority": 20000
    },
    {
        "name": "Hagezi DoH/VPN",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "priority": 30000,
        "location_ids": ["Home-Router"]
    }
]

# Execution
if __name__ == "__main__":
    logger.info("Starting Cloudflare Gateway Adblock Update...\n")
    logger.info(f"Fresh start: {'YES' if Fresh_Start else 'NO'}")
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

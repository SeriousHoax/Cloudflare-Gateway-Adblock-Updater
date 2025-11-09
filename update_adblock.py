import requests
import json
import os
import sys
import time

# Get env vars from GitHub secrets
api_token = os.environ.get('CLOUDFLARE_API_TOKEN')
account_id = os.environ.get('CLOUDFLARE_ACCOUNT_ID')

if not api_token or not account_id:
    print("Error: Missing API token or account ID.")
    sys.exit(1)

# API base URL
base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

# Helper function for API requests with retries
def api_request(method, url, data=None, retries=3, backoff_factor=5):
    for attempt in range(retries):
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=json.dumps(data))
            elif method == 'PUT':
                response = requests.put(url, headers=headers, data=json.dumps(data))
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)
            else:
                raise ValueError("Unsupported method")

            if response.status_code >= 500 and attempt < retries - 1:
                # Retry on 5xx server errors
                sleep_time = backoff_factor * (2 ** attempt)
                print(f"Server error {response.status_code} on {method} {url}. Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
                continue

            return response
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                sleep_time = backoff_factor * (2 ** attempt)
                print(f"Request exception on {method} {url}: {e}. Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
                continue
            raise e

# Helper function to check API response
def check_api_response(response, action):
    if response.status_code != 200:
        print(f"Error {action}: {response.status_code} - {response.text}")
        sys.exit(1)
    data = response.json()
    if not data.get('success', False):
        print(f"API success false during {action}: {json.dumps(data)}")
        sys.exit(1)
    return data

# Define blocklists with names, primary URLs, and jsDelivr backup URLs
blocklists = [
    {
        "name": "Hagezi Pro++",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt"
    },
    {
        "name": "Hagezi-DoHVPN",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt"
    },
    {
        "name": "Samsung-native",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.samsung-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt"
    },
    {
        "name": "Vivo-native",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.vivo-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.vivo-onlydomains.txt"
    },
    {
        "name": "OppoRealme-native",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.oppo-realme-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.oppo-realme-onlydomains.txt"
    },
    {
        "name": "Xiaomi-native",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.xiaomi-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt"
    },
    {
        "name": "TikTok-native",
        "url": "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/native.tiktok-onlydomains.txt",
        "backup_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok-onlydomains.txt"
    }
]

# Pre-cleanup: Delete all old adblock-related policies and lists...
print("\nPerforming global cleanup of old adblock policies and lists...")

# Cleanup old policies first
old_policy_names = ["Block Ads", "Block Hagezi ProPlus", "Block Hagezi DoHVPN", "Block Hagezi Samsung", "Block Hagezi Vivo", "Block Hagezi OppoRealme", "Block Hagezi Xiaomi", "Block Hagezi TikTok", "Block Hagezi Pro++", "Block Hagezi-DoHVPN", "Block Hagezi Samsung-native", "Block Hagezi Vivo-native", "Block Hagezi OppoRealme-native", "Block Hagezi Xiaomi-native", "Block Hagezi TikTok-native"]  # Add any other old names

response = api_request('GET', f"{base_url}/rules")
data = check_api_response(response, "getting rules for cleanup")
rules = data.get('result') or []

for rule in rules:
    if rule['name'] in old_policy_names:
        delete_response = api_request('DELETE', f"{base_url}/rules/{rule['id']}")
        check_api_response(delete_response, f"deleting old policy {rule['name']}")
        print(f"Cleaned up old policy: {rule['name']}")

# Now cleanup old lists (safe after policies are deleted)
old_prefixes = ["Adblock_List_", "ProPlus_List_", "DoHVPN_List_", "Samsung_List_", "Vivo_List_", "OppoRealme_List_", "Xiaomi_List_", "TikTok_List_", "Hagezi_Pro++_List_", "Hagezi-DoHVPN_List_", "Samsung-native_List_", "Vivo-native_List_", "OppoRealme-native_List_", "Xiaomi-native_List_", "TikTok-native_List_"]  # Add any other old prefixes if needed

response = api_request('GET', f"{base_url}/lists")
data = check_api_response(response, "getting lists for cleanup")
lists = data.get('result') or []

for lst in lists:
    if any(lst['name'].startswith(prefix) for prefix in old_prefixes):
        delete_response = api_request('DELETE', f"{base_url}/lists/{lst['id']}")
        check_api_response(delete_response, f"deleting old list {lst['name']}")
        print(f"Cleaned up old list: {lst['name']}")

# Process each blocklist separately
for bl in blocklists:
    filter_name = bl["name"]
    primary_url = bl["url"]
    backup_url = bl.get("backup_url")
    list_prefix = f"{filter_name.replace(' ', '_')}_List_"  # Replace spaces with underscores for prefix
    policy_name = f"Block {filter_name}"

    print(f"\nProcessing filter: {filter_name}")

    # Step 1: Fetch the blocklist (try primary, then backup)
    fetched = False
    for url in [primary_url, backup_url]:
        if url is None:
            continue
        response = api_request('GET', url)
        if response.status_code == 200:
            fetched = True
            print(f"Successfully fetched from {url}")
            break
        else:
            print(f"Failed to fetch from {url}: {response.status_code}. Trying next...")

    if not fetched:
        print(f"Error fetching blocklist for {filter_name} from all sources. Skipping.")
        continue

    # Process the list: skip comments, trim, unique
    lines = response.text.splitlines()
    domains = set()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            domains.add(line)

    domains = list(domains)
    print(f"Fetched and processed {len(domains)} unique domains for {filter_name}.")

    if not domains:
        print(f"No domains for {filter_name}. Skipping.")
        continue

    # Step 2: Split into chunks of 1000
    chunk_size = 1000
    chunks = [domains[i:i + chunk_size] for i in range(0, len(domains), chunk_size)]
    print(f"Split {filter_name} into {len(chunks)} chunks.")

    # Step 3: Delete existing policy if it exists (to detach lists)
    response = api_request('GET', f"{base_url}/rules")
    data = check_api_response(response, "getting rules")
    rules = data.get('result') or []

    adblock_rule = next((rule for rule in rules if rule['name'] == policy_name), None)
    if adblock_rule:
        rule_id = adblock_rule['id']
        delete_response = api_request('DELETE', f"{base_url}/rules/{rule_id}")
        check_api_response(delete_response, f"deleting policy for {filter_name}")
        print(f"Deleted existing policy: {policy_name}")

    # Step 4: Delete old lists for this filter (named {list_prefix}*)
    response = api_request('GET', f"{base_url}/lists")
    data = check_api_response(response, "getting lists")
    lists = data.get('result') or []

    for lst in lists:
        if lst['name'].startswith(list_prefix):
            delete_response = api_request('DELETE', f"{base_url}/lists/{lst['id']}")
            check_api_response(delete_response, f"deleting list {lst['name']} for {filter_name}")
            print(f"Deleted old list: {lst['name']}")

    # Step 5: Create new lists and collect their IDs
    list_ids = []
    for i, chunk in enumerate(chunks, 1):
        list_name = f"{list_prefix}{i}"
        data_payload = {
            "name": list_name,
            "type": "DOMAIN",
            "description": f"{filter_name} Adblock Chunk",
            "items": [{"value": domain} for domain in chunk]
        }
        response = api_request('POST', f"{base_url}/lists", data_payload)
        create_data = check_api_response(response, f"creating list {list_name} for {filter_name}")
        list_id = create_data['result']['id']
        list_ids.append(list_id)
        print(f"Created list: {list_name} with {len(chunk)} items (ID: {list_id}).")

    # Step 6: Create the DNS blocking policy
    if list_ids:
        expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
    else:
        print(f"No lists created for {filter_name}. Skipping policy.")
        continue

    data_payload = {
        "action": "block",
        "description": f"Block using {filter_name} list",
        "enabled": True,
        "filters": ["dns"],
        "name": policy_name,
        "traffic": expression
    }

    response = api_request('POST', f"{base_url}/rules", data_payload)
    check_api_response(response, f"creating policy for {filter_name}")
    print(f"Created new policy: {policy_name}")

print("\nUpdate complete for all filters!")

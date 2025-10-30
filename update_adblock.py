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

# Step 1: Fetch the Hagezi Pro++ blocklist
blocklist_url = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt"
response = api_request('GET', blocklist_url)  # Note: This is external, but we can retry
if response.status_code != 200:
    print(f"Error fetching blocklist: {response.status_code}")
    sys.exit(1)

# Process the list: skip comments, trim, unique
lines = response.text.splitlines()
domains = set()  # Use set for unique
for line in lines:
    line = line.strip()
    if line and not line.startswith('#'):
        domains.add(line)

domains = list(domains)
print(f"Fetched and processed {len(domains)} unique domains.")

# Step 2: Split into chunks of 1000 (free plan limit per list)
chunk_size = 1000
chunks = [domains[i:i + chunk_size] for i in range(0, len(domains), chunk_size)]
print(f"Split into {len(chunks)} chunks.")

# Step 3: Delete existing policy if it exists (to detach lists)
response = api_request('GET', f"{base_url}/rules")
data = check_api_response(response, "getting rules")
rules = data.get('result') or []  # Handle None as []

adblock_rule = next((rule for rule in rules if rule['name'] == 'Block Ads'), None)
if adblock_rule:
    rule_id = adblock_rule['id']
    delete_response = api_request('DELETE', f"{base_url}/rules/{rule_id}")
    check_api_response(delete_response, "deleting policy")
    print("Deleted existing Block Ads policy to detach lists.")

# Step 4: Delete old lists (named Adblock_List_*)
response = api_request('GET', f"{base_url}/lists")
data = check_api_response(response, "getting lists")
lists = data.get('result') or []  # Handle None as []

for lst in lists:
    if lst['name'].startswith('Adblock_List_'):
        delete_response = api_request('DELETE', f"{base_url}/lists/{lst['id']}")
        check_api_response(delete_response, f"deleting list {lst['name']}")
        print(f"Deleted old list: {lst['name']}")

# Step 5: Create new lists and collect their IDs
list_ids = []
for i, chunk in enumerate(chunks, 1):
    list_name = f"Adblock_List_{i}"
    data_payload = {
        "name": list_name,
        "type": "DOMAIN",
        "description": "Hagezi Pro++ Adblock Chunk",
        "items": [{"value": domain} for domain in chunk]
    }
    response = api_request('POST', f"{base_url}/lists", data_payload)
    create_data = check_api_response(response, f"creating list {list_name}")
    list_id = create_data['result']['id']
    list_ids.append(list_id)
    print(f"Created list: {list_name} with {len(chunk)} items (ID: {list_id}).")

# Step 6: Create the DNS blocking policy
# Build expression for domain + subdomain blocking: any(dns.domains[*] in $id1) or any(dns.domains[*] in $id2) or ...
if list_ids:
    expression = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
else:
    print("No lists created. Skipping policy.")
    sys.exit(0)

data_payload = {
    "action": "block",
    "description": "Block ads using Hagezi Pro++ list",
    "enabled": True,
    "filters": ["dns"],
    "name": "Block Ads",
    "traffic": expression
}

response = api_request('POST', f"{base_url}/rules", data_payload)
check_api_response(response, "creating policy")
print("Created new Block Ads policy.")

print("Update complete!")

import requests
import json
import os
import sys

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
response = requests.get(blocklist_url)
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

# Step 3: Delete old lists (named Adblock_List_*)
response = requests.get(f"{base_url}/lists", headers=headers)
data = check_api_response(response, "getting lists")
lists = data.get('result') or []  # Handle None as []

for lst in lists:
    if lst['name'].startswith('Adblock_List_'):
        delete_response = requests.delete(f"{base_url}/lists/{lst['id']}", headers=headers)
        check_api_response(delete_response, f"deleting list {lst['name']}")
        print(f"Deleted old list: {lst['name']}")

# Step 4: Create new lists
list_names = []
for i, chunk in enumerate(chunks, 1):
    list_name = f"Adblock_List_{i}"
    data_payload = {
        "name": list_name,
        "type": "DOMAIN",
        "description": "Hagezi Pro++ Adblock Chunk",
        "items": [{"value": domain} for domain in chunk]
    }
    response = requests.post(f"{base_url}/lists", headers=headers, data=json.dumps(data_payload))
    create_data = check_api_response(response, f"creating list {list_name}")
    print(f"Created list: {list_name} with {len(chunk)} items.")
    list_names.append(list_name)

# Step 5: Create or update the DNS blocking policy
# Build expression: hostname in $Adblock_List_1 or hostname in $Adblock_List_2 or ...
if list_names:
    expression = " or ".join([f'hostname in ${name}' for name in list_names])
else:
    print("No lists created. Skipping policy.")
    sys.exit(0)

# Check if policy exists
response = requests.get(f"{base_url}/rules", headers=headers)
data = check_api_response(response, "getting rules")
rules = data.get('result') or []  # Handle None as []

adblock_rule = next((rule for rule in rules if rule['name'] == 'Block Ads'), None)

data_payload = {
    "action": "block",
    "description": "Block ads using Hagezi Pro++ list",
    "enabled": True,
    "filters": ["dns"],
    "name": "Block Ads",
    "traffic": expression
}

if adblock_rule:
    # Update existing rule
    rule_id = adblock_rule['id']
    response = requests.put(f"{base_url}/rules/{rule_id}", headers=headers, data=json.dumps(data_payload))
    check_api_response(response, "updating policy")
    print("Updated existing Block Ads policy.")
else:
    # Create new rule
    response = requests.post(f"{base_url}/rules", headers=headers, data=json.dumps(data_payload))
    check_api_response(response, "creating policy")
    print("Created new Block Ads policy.")

print("Update complete!")

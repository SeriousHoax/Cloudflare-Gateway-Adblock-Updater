# Cloudflare Gateway Adblock Updater - Cleanup Script
# Description: 
# Deletes only the Cloudflare Gateway policies and lists created by update_gateway.py. 
# Manually created policies are not affected.
#
# GitHub: https://github.com/SeriousHoax
# License: MIT

import asyncio
import logging
import aiohttp
import sys

# Import shared configuration and helpers from the main script
from update_gateway import (
    blocklists, 
    headers, 
    base_url, 
    get_all_paginated, 
    async_delete_lists_batch,
    api_request,
    check_api_response,
    MAX_CONCURRENT_REQUESTS
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    logger.info("🎬 Starting Cloudflare Gateway Adblock Cleanup...")
    logger.info("⚠️ This script will DELETE all policies and lists created by update_gateway.py")
    logger.info(f"🎯 Targeting {len(blocklists)} filters from configuration.\n")

    # 1. Fetch all current policies and lists ONCE to avoid repeated API calls
    logger.info("📡 Fetching current Cloudflare Gateway Blocking policies and lists...")
    try:
        all_policies = get_all_paginated(f"{base_url}/rules")
        all_lists = get_all_paginated(f"{base_url}/lists")
        logger.info(f"📋 Found {len(all_policies)} policies and {len(all_lists)} lists total.\n")
    except Exception as e:
        logger.error(f"🚫 Failed to fetch initial data: {e}")
        sys.exit(1)

    async with aiohttp.ClientSession(headers=headers) as session:
        for bl in blocklists:
            filter_name = bl['name']
            logger.info(f"🧵 Processing cleanup for: {filter_name}")

            # --- Delete Policy ---
            policy_name = filter_name
            policy_to_delete = next((p for p in all_policies if p['name'] == policy_name), None)
            
            if policy_to_delete:
                logger.info(f"  ℹ️ Found policy '{policy_name}' (ID: {policy_to_delete['id']}). Deleting...")
                try:
                    resp = api_request('DELETE', f"{base_url}/rules/{policy_to_delete['id']}")
                    check_api_response(resp, f"deleting policy {policy_name}")
                except Exception as e:
                    logger.error(f"  🚫 Failed to delete policy {policy_name}: {e}")
            else:
                logger.info(f"  ℹ️ Policy '{policy_name}' not found.")

            # --- Delete Lists ---
            # List name pattern: {FilterName}_List_{Number}
            list_prefix = f"{filter_name.replace(' ', '_')}_List_"
            
            lists_to_delete = [l for l in all_lists if l['name'].startswith(list_prefix)]
            
            if lists_to_delete:
                logger.info(f"  ℹ️ Found {len(lists_to_delete)} lists matching prefix '{list_prefix}'. Deleting...")
                await async_delete_lists_batch(lists_to_delete)
            else:
                logger.info(f"  ℹ️ No lists found matching prefix '{list_prefix}'.")
            
            logger.info("")

    logger.info("✨ Cleanup completed successfully!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n🛑 Cleanup cancelled by user.")
    except Exception as e:
        logger.error(f"🚫 Unexpected error: {e}", exc_info=True)

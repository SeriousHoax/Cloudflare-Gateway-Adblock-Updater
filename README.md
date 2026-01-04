# Cloudflare Gateway Adblock Updater

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The Python script in this repository automates updating your Cloudflare Zero Trust Gateway policy with the highly recommended and effective [Hagezi](https://github.com/hagezi/dns-blocklists) Multi Pro++ DNS filter list.

## Features

- **Automated DNS filter updates**

  Automatically downloads and updates the Hagezi Multi Pro++ DNS blocklist in Cloudflare Zero Trust Gateway.

- **Cloudflare free-plan aware list handling**

  Splits large blocklists into 1,000-domain chunks to stay within Cloudflare’s free-tier limit of 300 lists (up to 300K domains total).

- **Zero-Downtime with smart synchronization of existing lists**

  Detects and synchronizes existing Gateway lists and policies with the updated filters, ensuring outdated domains are removed and new ones are added without unnecessary recreation.

- **Automatic policy creation and updates**

  Creates the required Gateway policy if it does not exist and keeps it updated to reference the correct blocklists.

- **Force cleanup / full rebuild mode**

  Supports a `FRESH_START=true` environment variable to:
  - Remove all existing Gateway lists and policies
  - Recreate everything cleanly using the latest filters
  Useful for CI workflows or when a full reset is required.

- **GitHub Workflow integration**

  Designed to run seamlessly via GitHub Actions or on your local device, making scheduled and hands-off updates easy.

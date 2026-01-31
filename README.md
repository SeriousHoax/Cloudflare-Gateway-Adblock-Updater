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

- **Fast async API operations**

  Uses async, parallel requests to update Cloudflare Gateway lists efficiently, significantly reducing execution time while respecting Cloudflare API rate limits.

- **Automatic policy creation and updates**

  Creates the required Gateway policy if it does not exist and keeps it updated to reference the correct blocklists.

- **Force cleanup / full rebuild mode**

  Supports a `FRESH_START=true` environment variable to:
  - Remove all existing Gateway lists and policies
  - Recreate everything cleanly using the latest filters
  Useful for CI workflows or when a full reset is required.

- **GitHub Workflow integration**

  Designed to run seamlessly via GitHub Actions or on your local device, making scheduled and hands-off updates easy.


# Setup Guide

## Cloudflare credentials

- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account identifier used to build the Gateway API URL.
- `CLOUDFLARE_API_TOKEN` — API token with Zero Trust/Gateway permissions for the updater to read and manage Gateway lists/policies.

Use the exact names above as repository secrets so workflows can reference them directly (the scripts expect those environment variable names).

### Get the values from Cloudflare Zero Trust

1. Sign in to Cloudflare at [Cloudflare Dashboard](https://dash.cloudflare.com) and open your account (Account Home or any domain dashboard).
2. Locate your account ID: the long hex-like 32-character string of letters and numbers appears in the dashboard URL. Example URL:

```text
https://dash.cloudflare.com/1234567890abcdef1234567890abcdef
```

The `1234567890abcdef1234567890abcdef` portion is your `CLOUDFLARE_ACCOUNT_ID`.

3. Create an API token:
   - Go to your profile's API tokens page: [Cloudflare API-Tokens](https://dash.cloudflare.com/profile/api-tokens)
   - Click **Create Token** and choose **Create Custom Token**.
   - Give the token your preferred name.
   - Add the following under the **Permissions** section:
     * **Account** | **Zero Trust** | **Read**
     * **Account** | **Zero Trust** | **Edit** 
   - Click **Continue to summary**, then click **Create Token**.
   - **Copy the token immediately** as Cloudflare only shows it once.

<img width="3336" height="3984" alt="dash" src="https://github.com/user-attachments/assets/ad9b9b64-c794-4614-8821-2cbb206dfcd1" />

Security note: keep the token secret. Use GitHub repository secrets rather than committing values to the repo. Also, store the token in a safe place outside of GitHub if required.

## GitHub Configuration
Next you should create a fork of this project on your GitHub. You can do this by clicking the "**Fork**" button in the top right of my repo's page.

### Add the values to GitHub as Actions secrets

1. Open your GitHub repository and go to **Settings** → **Secrets and variables** → **Actions**.
2. Click **New repository secret**.
3. Add the following secrets (exact names):
   - **Name:** `CLOUDFLARE_API_TOKEN` — **Value:** the API token you copied.
   - **Name:** `CLOUDFLARE_ACCOUNT_ID` — **Value:** your account ID string.

### Ensure Actions permission and workflow access

- Go to **Settings** → **Actions** → **General** in the repository and confirm workflows are allowed to run.

## GitHub Workflow
You should configure your GitHub Workflow file to suit your needs. The updater workflow in my main branch refers to my personal branch, which you should avoid using. You should edit your workflow file to remove that reference. An example GitHub workflow file should look like this: [Example Workflow File](https://github.com/SeriousHoax/Cloudflare-Gateway-Adblock-Updater/blob/personal/.github/workflows/update-gateway.yml)

## Troubleshooting

- If the action fails immediately with an auth error, double-check the secret names and values.

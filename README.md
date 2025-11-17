# Cloudflare Gateway Adblock Updater

This repository automates updating the Cloudflare Gateway (Zero Trust) with the [Hagezi](https://github.com/hagezi/dns-blocklists) Multi Pro++, Dynamic DNS as well as Native trackers including Samsung, Vivo, OPPO/Realme, Xiaomi and TikTok filter list using GitHub Actions. It fetches the list daily at a given time, processes it (removing duplicates, splitting into 1,000-domain chunks), deletes old lists/policies, creates new ones, and sets up a DNS blocking policy that covers domains and subdomains.

Cloudflare's free plan supports up to 300 lists with no more than 1,000 domains in each list (300x1000 = 300K rules max), which is why the list must be split.

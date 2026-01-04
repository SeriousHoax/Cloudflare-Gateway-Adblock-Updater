# Cloudflare Gateway Adblock Updater

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The Python script in this repository automates updating your Cloudflare Zero Trust Gateway policy with the highly recommended and effective [Hagezi](https://github.com/hagezi/dns-blocklists) Multi Pro++ DNS filter list.

Cloudflare's free plan supports up to 300 lists with no more than 1,000 domains in each list (300x1000 = 300K rules max), which is why the domains are split into 1,000-domain chunks per list.

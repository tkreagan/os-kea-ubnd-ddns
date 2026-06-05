---
name: Bug report
about: Something isn't working as expected
labels: bug
---

## Describe the bug

A clear description of what is happening and what you expected to happen.

## Environment

| | Version |
|---|---|
| OPNsense | e.g. 26.1 |
| Kea DHCP | e.g. 2.6.1 |
| os-kea-unbound | e.g. 0.9 |

## Configuration

Which sync/cleanup features are enabled in **Services → Kea Unbound DDNS → Settings**?

- [ ] Sync Kea static reservations
- [ ] Sync Kea active leases
- [ ] Clean up old IPs on lease update
- [ ] Automatically clean stale DNS records
- [ ] TSIG authentication

Are you using the dynamic path (kea-dhcp-ddns running and configured), the static
path (sync only), or both?

## Steps to reproduce

1. 
2. 
3. 

## What you observed

Paste relevant output from **Services → Kea Unbound DDNS → Log File**, or from
the shell:

```
sudo tail -n 50 /var/log/keaunbound/keaunbound_$(date +%Y%m%d).log
```

If the issue relates to DNS registration state, paste the output of the Lease
Audit tab or:

```
sudo /usr/local/opnsense/scripts/keaunbound/local-data-audit.py --report-json | python3 -m json.tool
```

## Additional context

<!-- Anything else that might help — subnet config, DHCP client behaviour, etc. -->

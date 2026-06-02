# Kea Unbound DDNS Plugin - Test Suite Brief

## Executive Summary

This OPNsense plugin bridges Kea DHCP server and Unbound DNS resolver, automatically registering DHCP leases and static reservations in DNS. It implements RFC 2136 DNS UPDATE protocol with optional TSIG authentication, eliminating manual DNS management for DHCP clients.

## The Problem

When using Kea DHCP and Unbound DNS on OPNsense:
- Static DHCP reservations must be manually added to DNS
- Active DHCP leases don't automatically appear in DNS
- Users must maintain DNS entries separately from DHCP
- Changes in one system don't sync to the other
- No visibility into registration status

## The Solution

This plugin creates an automated bridge:

```
Kea DHCP (leases + reservations)
         ↓ (RFC 2136 DNS UPDATE)
   KeaUnbound Plugin
         ↓ (unbound-control)
   Unbound DNS (local_data entries)
```

Two synchronization paths:
1. **Dynamic**: DHCP-DDNS daemon sends RFC 2136 updates for leases as they're assigned
2. **Static**: Plugin pulls Kea reservations directly and registers them

## Core Functionality

### 1. Stub DNS Server
- Listens on UDP 127.0.0.1:53535 (configurable)
- Receives RFC 2136 DNS UPDATE packets from Kea DHCP-DDNS daemon
- Validates TSIG signatures (if enabled)
- Translates updates to Unbound local_data entries via unbound-control
- Handles A, AAAA, and PTR records automatically
- Graceful error handling for network issues

### 2. Static Reservation Sync
- Queries Kea Control Agent API for static DHCP reservations
- Registers each reservation as A/AAAA record + PTR record in Unbound
- Skips entries already in OPNsense host_entries.conf (avoids duplication)
- Runs manually on demand or at startup
- Supports --dry-run and --verbose flags

### 3. Dynamic Lease Sync
- Queries Kea Control Agent API for active DHCP leases
- Registers each lease with TTL = remaining lease lifetime (self-healing)
- Automatically removes entries when leases expire
- Supports IPv4 and IPv6
- Runs at startup and periodically
- Supports --dry-run and --verbose flags

### 4. Comprehensive Audit
- Checks all DNS entries across four sources:
  - Kea static reservations
  - Kea active leases
  - Unbound local_data entries
  - OPNsense host_entries.conf
- Categorizes each entry status:
  - **OK**: Forward record + PTR both present in Unbound
  - **Missing-PTR**: Forward present but PTR missing
  - **Stale**: In Unbound but not in any Kea source (orphaned)
  - **Orphaned-PTR**: PTR without matching forward record
  - **Static**: In host_entries.conf (OPNsense-managed)
- Gracefully degrades when Kea unavailable
- Returns JSON for API consumption

### 5. Stale Record Cleanup
- Identifies and removes stale/orphaned DNS entries
- Default mode: automatic cleanup with reporting (cron-friendly)
- --confirm flag: interactive mode for manual debugging
- --dry-run flag: preview changes without applying
- Removes only entries not tied to Kea reservations or active leases

### 6. Web UI - Three Tabs

#### Settings Tab
- Enable/disable plugin and features
- TSIG authentication configuration
- Manual sync buttons (Sync Reservations, Sync Leases, Clean Stale Records)
- Auto-cleanup scheduling (6h, 12h, 24h intervals)
- Built-in comprehensive documentation (help toggle)

#### Kea Config Check Tab
- Displays Kea subnet configuration status
- Shows which subnets have DDNS enabled
- IPv4 and IPv6 subnets listed separately
- Summary: How many configured vs not configured
- Actionable alerts directing users to documentation

#### Lease Audit Tab
- Complete DNS registration status view
- Summary statistics cards (OK, Missing PTR, Stale, Orphaned, Static)
- Table of all registered entries with status
- Orphaned PTRs table for cleanup guidance
- Auto-refresh every 30 seconds
- Color-coded status indicators

## User Workflows

### Workflow 1: Enable DDNS for a Subnet
1. User configures Kea DHCP-DDNS daemon (outside plugin)
2. User enables DDNS in Kea subnet config (sets `ddns-send-updates: true`)
3. User checks "Kea Config Check" tab to verify configuration
4. New leases automatically appear in DNS as assigned
5. User can click "Sync Leases Now" to update existing entries

### Workflow 2: Add Static Reservation
1. User creates DHCP static reservation in Kea
2. User clicks "Sync Static Reservations Now" in Settings
3. Reservation immediately appears in DNS (A/AAAA/PTR)
4. User can see it in "Lease Audit" tab

### Workflow 3: Verify DNS Status
1. User clicks "Lease Audit" tab
2. Sees all registered DNS entries across all sources
3. Can identify:
   - Missing PTR records (forward exists but reverse doesn't)
   - Stale entries (in DNS but not in Kea)
   - Orphaned PTRs (reverse without forward)
4. Clicks "Clean Stale Records Now" if needed

### Workflow 4: Troubleshooting
1. User checks "Kea Config Check" to verify subnets configured
2. User checks "Lease Audit" to see actual registration status
3. Checks logs (Log File tab) for errors
4. Reads Settings documentation for configuration help

## Error Handling & Graceful Degradation

### When Kea Control Agent is Down
- Static sync fails with clear error (shows in logs)
- Lease sync fails with clear error (shows in logs)
- Audit still works - shows available data without Kea info
- Config Check shows clear error message
- Plugin continues running, doesn't crash

### When Unbound is Down
- Update packets fail to write
- Logged as error in syslog
- Automatic cleanup skipped
- Service can restart independently

### When Services Restart
- Plugin detects startup via hooks (kea_start, unbound_start, bootup)
- Automatically syncs reservations and leases
- No manual intervention needed
- Race-condition safe (three hooks, same function)

### When Kea Config Changes
- Next sync picks up new subnets
- Manual "Sync Now" buttons available
- Optional auto-reload of Unbound (configurable)

### TTL Expiration (Self-Healing)
- Leases registered with TTL = remaining lease time
- As TTL expires, entries automatically removed from DNS
- No cleanup job needed for expired leases
- Stale cleanup only removes non-expiring entries

## Configuration

### Plugin Settings
- **enabled**: Enable/disable entire plugin
- **port**: Listener port (default 53535)
- **sync_static_reservations**: Sync Kea reservations to Unbound
- **sync_dynamic_leases**: Sync Kea leases to Unbound
- **enable_auto_clean**: Periodically remove stale records
- **auto_clean_interval**: 6h, 12h, or 24h cleanup frequency
- **enable_tsig**: Require TSIG signatures on DNS updates
- **tsig_key_name**: TSIG key identifier
- **tsig_key_secret**: Base64-encoded HMAC secret
- **tsig_algorithm**: HMAC-MD5, HMAC-SHA1, or HMAC-SHA256
- **reload_unbound_on_kea_sync**: Reload Unbound when Kea config changes

### Required Kea Configuration (User's Responsibility)
Per subnet that should sync:
```json
{
  "subnet4": [
    {
      "subnet": "10.0.0.0/24",
      "ddns-send-updates": true,           // Required
      "ddns-override-no-update": true,     // Recommended
      "ddns-override-client-update": true, // Recommended
      "hostname-char-replacement": "-"     // Optional
    }
  ]
}
```

Plus DHCP-DDNS daemon must be configured to send to 127.0.0.1:53535.

## Success Criteria

### Plugin is Working Correctly When:
1. Static Kea reservations appear in DNS as A/AAAA/PTR records
2. Active DHCP leases appear in DNS with correct TTL
3. Lease Audit shows "OK" status for properly registered entries
4. Expired leases automatically disappear from DNS
5. Kea Config Check shows correct DDNS configuration status
6. Stale cleanup removes orphaned entries
7. Manual sync buttons work immediately
8. Auto-cleanup runs on configured schedule
9. TSIG validation works (if enabled)
10. Plugin handles Kea unavailability gracefully with clear errors

## Known Limitations

1. **Unbound-only**: Works with Unbound resolver only, not other DNS servers
2. **Local only**: Stub server only listens on 127.0.0.1 (intentional for security)
3. **No direct Kea editing**: Can view Kea config but cannot modify it from OPNsense
4. **Single TSIG key**: One key for all updates (could expand in future)
5. **No query forwarding**: Only UPDATE packets, not DNS queries

## Testing Focus Areas

### Critical Path (Must Pass)
- [ ] Plugin enables/disables correctly
- [ ] Static reservations sync to Unbound
- [ ] Leases sync with correct TTL
- [ ] Audit shows accurate status
- [ ] Stale cleanup removes orphaned entries
- [ ] TSIG validation works (if enabled)
- [ ] Graceful degradation when Kea down

### User-Facing (Must Work)
- [ ] All three UI tabs load
- [ ] Manual sync/clean buttons work
- [ ] Auto-refresh works in tabs
- [ ] Help documentation appears
- [ ] Error messages are clear and actionable
- [ ] Kea Config Check matches actual config

### Edge Cases (Should Handle)
- [ ] 100+ DNS entries
- [ ] Multiple IPv4 + IPv6 subnets
- [ ] Rapid lease churn (many assignments/releases)
- [ ] Service restarts
- [ ] Kea Control Agent brief outages
- [ ] TTL transitions to zero
- [ ] Concurrent requests to UI
- [ ] Very long hostnames
- [ ] Special characters in hostnames

### Data Integrity (Cannot Lose Data)
- [ ] Audit data matches actual Unbound entries
- [ ] No duplicate entries created
- [ ] No entries accidentally deleted
- [ ] Stale cleanup doesn't touch static entries
- [ ] Config changes persist correctly

## Deliverables Expected

1. **Unit Tests** - Test individual components in isolation
2. **Integration Tests** - Test components working together
3. **UI Tests** - Test web interface functionality
4. **End-to-End Tests** - Test complete workflows
5. **Error Handling Tests** - Verify graceful degradation
6. **Performance Tests** - Verify scale and response times
7. **Test Report** - Document test results and coverage
8. **Issues/Bugs Found** - Any problems discovered during testing

---

**Plugin Version**: 1.0.0-rc1  
**Base Framework**: OPNsense (MVC, Volt templates, configd actions)  
**Backend**: Python 3, Shell scripts  
**Frontend**: Bootstrap 5, jQuery/AJAX  
**Protocols**: RFC 2136 (DNS UPDATE), TSIG (RFC 2845)  
**Dependencies**: Kea DHCP, Unbound DNS, OPNsense framework

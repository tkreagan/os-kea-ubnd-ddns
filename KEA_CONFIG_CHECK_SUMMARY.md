# Kea Config Check Implementation Summary

## Overview
Implemented a complete DDNS configuration verification system that allows users to check which Kea subnets are configured for DDNS and view configuration status.

## Components Created

### 1. API Controller: KcaConfigController.php
**Location**: `src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/Api/KcaConfigController.php`

**Endpoint**: GET `/api/keaunbound/kca-config/check`

**Functionality**:
- Queries Kea Control Agent for DHCPv4 and DHCPv6 configurations
- Extracts subnet information from running Kea config
- Checks `ddns-send-updates` setting for each subnet
- Returns structured JSON with subnet status
- Gracefully handles Kea unavailability with clear error messages

**Response Structure**:
```json
{
  "status": "ok" | "error",
  "kea_error": null | "error message",
  "ipv4_subnets": [
    {
      "subnet": "10.0.0.0/24",
      "ddns_enabled": true,
      "status": "configured",
      "comment": "office network"
    }
  ],
  "ipv6_subnets": [...]
}
```

### 2. Web UI Controller: KcaConfigController.php
**Location**: `src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/KcaConfigController.php`

- Simple controller that renders the kcaconfig view
- Route: `/ui/keaunbound/kcaconfig`
- Action: `kcaconfigAction()`

### 3. View Template: kcaconfig.volt
**Location**: `src/opnsense/mvc/app/views/OPNsense/KeaUnbound/kcaconfig.volt`

#### Features:
- **Auto-refresh**: Updates every 30 seconds
- **Manual refresh**: "Refresh Now" button
- **Summary Statistics**:
  - Cards showing: Configured, Not Configured, Total Subnets
  - Color-coded display
  
- **IPv4 and IPv6 Subnet Tables**:
  - Columns: Subnet | DDNS Enabled | Status | Comment
  - Status badges:
    - 🟢 Configured (green)
    - 🟡 Not Configured (yellow)
  - DDNS Enabled column: ✅ Yes or ❌ No
  - Comment field for subnet descriptions
  
- **Guidance Alerts**:
  - If subnets not configured: "Action Needed" alert with next steps
  - If all configured: Success message
  
- **Error Handling**:
  - Connection errors
  - Kea Control Agent not running
  - Timeout handling
  - All errors shown in dismissible alert boxes

### 4. Menu Integration
**File**: `src/opnsense/mvc/app/models/OPNsense/KeaUnbound/Menu/Menu.xml`

Menu structure:
```xml
<KeaUnbound>
  <General order="10" VisibleName="Settings" url="/ui/keaunbound/index"/>
  <KcaConfig order="20" VisibleName="Kea Config Check" url="/ui/keaunbound/kcaconfig"/>
  <Audit order="50" VisibleName="Lease Audit" url="/ui/keaunbound/status"/>
  <LogFile order="100" VisibleName="Log File" url="/ui/diagnostics/log/core/kea-unbound-ddns"/>
</KeaUnbound>
```

### 5. Enhanced Documentation in Settings
**File**: `src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/forms/generalSettings.xml`

Added comprehensive "About Kea Unbound DDNS" documentation section that covers:
- How the plugin works
- Static reservations vs dynamic leases
- DDNS protocol explanation
- Step-by-step Kea configuration guide
- Example JSON configuration
- Setting explanations
- Feature list
- Tab descriptions

Visible via help toggle at top of settings page.

## Data Flow

```
User clicks "Kea Config Check" in menu
           ↓
Browser navigates to /ui/keaunbound/kcaconfig
           ↓
KcaConfigController.kcaconfigAction() routes to kcaconfig.volt
           ↓
kcaconfig.volt JavaScript calls /api/keaunbound/kca-config/check
           ↓
KcaConfigController.checkAction() (API)
           ↓
Queries Kea Control Agent: POST /
           Command: "dhcp4-get-config"
           Command: "dhcp6-get-config"
           ↓
Parses response for subnet config
           ↓
Returns JSON with subnet status
           ↓
kcaconfig.volt renders tables with subnet configuration
           ↓
User sees which subnets are DDNS-configured
```

## Key Features

### Subnet Configuration Status
1. **Configured**: `ddns-send-updates: true` ✅
2. **Not Configured**: `ddns-send-updates: false` or missing ❌

### Error Handling
- **Kea Control Agent not running**: Clear error message
- **Kea DHCP not responding**: Timeout handling
- **Config parsing error**: Graceful fallback
- All errors actionable and user-friendly

### Smart Alerts
- **Action Needed**: Shows when unconfigured subnets exist
- **All Configured**: Success message when all subnets are ready
- **Summary Statistics**: Quick overview of configuration state

## Kea Configuration Examples

### Enable DDNS for a subnet
Add to your Kea DHCPv4 configuration:

```json
{
  "subnet4": [
    {
      "subnet": "10.0.0.0/24",
      "ddns-send-updates": true,
      "ddns-override-no-update": true,
      "ddns-override-client-update": true,
      "hostname-char-replacement": "-",
      "pools": [
        {
          "pool": "10.0.0.100 - 10.0.0.200"
        }
      ]
    }
  ]
}
```

### Required DHCP-DDNS daemon configuration
Make sure kea-dhcp-ddns is configured to send updates to this server:

```json
{
  "ip-address": "127.0.0.1",
  "port": 53535,
  "forward-ddns": {
    "ddns-domains": [
      {
        "name": "example.com."
      }
    ]
  }
}
```

## Testing Recommendations

1. **Normal Operation**:
   - Verify config check page loads with configured subnets
   - Confirm auto-refresh updates data
   - Test manual refresh button

2. **Multiple Subnets**:
   - Create several subnets with mixed DDNS settings
   - Verify status indicators are correct
   - Check summary statistics

3. **Kea Unavailable**:
   - Stop Kea Control Agent
   - Verify error message appears
   - Verify error is actionable

4. **IPv4 and IPv6**:
   - Configure IPv4 subnets
   - Configure IPv6 subnets
   - Verify both tables appear correctly

## Dependencies

- Kea DHCP server with Control Agent enabled
- Kea Control Agent running on 127.0.0.1:8000 (default)
- cURL library for PHP (usually built-in)
- OPNsense UI components and framework

## Complete Plugin Tabs

Now the plugin has a complete UI workflow:

1. **Settings** (order 10)
   - Configure plugin behavior
   - Enable/disable sync features
   - Set TSIG authentication
   - Manage auto-cleanup
   - Manual sync/clean buttons
   - Comprehensive documentation

2. **Kea Config Check** (order 20)
   - View subnet DDNS configuration in Kea
   - Quick status overview
   - Actionable alerts
   - Configuration guidance

3. **Lease Audit** (order 50)
   - View all registered DNS entries
   - Check status of each entry
   - See which entries are in Unbound
   - View orphaned records
   - Auto-refresh status

4. **Log File** (order 100)
   - View plugin logs
   - Troubleshooting information

## Future Enhancements

1. **Kea Configuration Editor**: Allow editing subnet settings directly from OPNsense
2. **Bulk Configuration**: Apply DDNS settings to multiple subnets at once
3. **Configuration Backup**: Save/restore Kea configurations
4. **Historical Tracking**: View changes to subnet configurations
5. **Alerts**: Notify if subnets become unconfigured
6. **Integration**: Show DDNS status in Kea dashboard

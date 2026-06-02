# Status View Implementation Summary

## Overview
Implemented a comprehensive DNS registration status view that shows the state of all DNS entries across Kea DHCP reservations, active leases, and Unbound local_data.

## Components Created

### 1. API Endpoint: StatusController.php
**Location**: `src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/Api/StatusController.php`

- **Method**: `auditAction()` - GET `/api/keaunbound/status/audit`
- **Functionality**:
  - Executes `local-data-audit.py --report-json` 
  - Parses and returns JSON response
  - Handles errors gracefully:
    - Script not found
    - Script execution failure
    - Invalid JSON output
- **Response**: JSON object with `status`, `audit` fields containing:
  - `complete`: Boolean indicating if Kea data was available
  - `kea_error`: Error message if Kea Control Agent was unavailable
  - `records`: Array of DNS records with status
  - `orphaned_ptrs`: Array of orphaned PTR records

### 2. Web UI Controller: StatusController.php
**Location**: `src/opnsense/mvc/app/controllers/OPNsense/KeaUnbound/StatusController.php`

- Simple controller that renders the status view
- Route: `/ui/keaunbound/status`
- Action: `statusAction()`

### 3. View Template: status.volt
**Location**: `src/opnsense/mvc/app/views/OPNsense/KeaUnbound/status.volt`

#### Features:
- **Auto-refresh**: Updates every 30 seconds
- **Manual refresh**: "Refresh Now" button
- **Summary statistics**:
  - Cards showing count of: OK, Missing PTR, Stale, Orphaned PTR, Static records
  - Color-coded with Bootstrap badge colors
  
- **Warning banner**: 
  - Displayed if Kea was unavailable
  - Shows the specific error message
  
- **DNS Records Table**:
  - Columns: Hostname | IP | Type | Source | Status | In Unbound | PTR
  - Status badges:
    - ✅ OK (green)
    - ⚠️ Missing PTR (yellow)
    - ℹ️ Stale (blue)
    - ❌ Orphaned PTR (red)
    - Static (gray)
  - Source badges: reservation | lease | unbound_local_data | static
  - In Unbound: Yes/No
  - PTR Registered: ✓/✗
  
- **Orphaned PTRs Table**:
  - Secondary table showing PTRs with no corresponding forward record
  - Columns: PTR Name | Data | Status
  - Includes explanatory text about what these are

#### Error Handling:
- Connection errors
- Request timeouts
- Invalid JSON responses
- Script not found
- All errors shown in dismissible alert boxes

### 4. Menu Integration
**File**: `src/opnsense/mvc/app/models/OPNsense/KeaUnbound/Menu/Menu.xml`

Added menu item:
```xml
<Status order="50" VisibleName="Status" url="/ui/keaunbound/status"/>
```

- Appears in Services > Kea Unbound > Status
- Order 50 places it between Settings (10) and Log File (100)

## Data Flow

```
User clicks "Status" in menu
           ↓
Browser navigates to /ui/keaunbound/status
           ↓
StatusController.statusAction() routes to status.volt
           ↓
status.volt JavaScript calls /api/keaunbound/status/audit
           ↓
StatusController.auditAction() (API)
           ↓
Executes: local-data-audit.py --report-json
           ↓
Returns JSON audit data
           ↓
status.volt renders tables and statistics
           ↓
User sees complete DNS registration status
```

## Key Features

### Graceful Degradation
- If Kea Control Agent is unavailable, the audit still runs
- Shows warning banner explaining what data is incomplete
- UI displays available data without Kea information
- `complete: false` flag indicates partial data

### Status Categories
1. **OK**: Forward record and PTR both in Unbound
2. **Missing PTR**: Forward record present but PTR absent (Unbound inconsistency)
3. **Stale**: Record in Unbound but not in Kea or host_entries (orphaned data)
4. **Orphaned PTR**: PTR in Unbound with no corresponding forward record
5. **Static**: Record from OPNsense host_entries.conf (not managed by plugin)

### Record Sources
- **Reservation**: From Kea static DHCP reservations
- **Lease**: From Kea active DHCP leases
- **Unbound Local Data**: Currently in Unbound's local_data
- **Static**: From OPNsense-managed host_entries.conf

## Styling
- Uses Bootstrap 5 classes for consistency with OPNsense UI
- Responsive table design
- Color-coded badges for quick status identification
- Summary cards with statistics
- Dismissible alert boxes
- Proper spacing and typography

## Testing Recommendations

1. **Normal Operation**:
   - Verify status view loads with active leases/reservations
   - Confirm auto-refresh updates data
   - Test manual refresh button

2. **Kea Unavailable**:
   - Stop kea-ctrl-agent
   - Refresh page
   - Verify warning banner appears
   - Verify status view still shows available data

3. **Stale Records**:
   - Verify cleanup job can be triggered from settings
   - Verify stale records appear in status view
   - Verify orphaned PTRs appear in secondary table

4. **Performance**:
   - Verify script completes in reasonable time (< 5 seconds)
   - Verify auto-refresh doesn't cause UI lag
   - Verify large number of records renders efficiently

## Dependencies

- `local-data-audit.py` script (must be installed)
- `python3` for script execution
- OPNsense UI components (mapDataToFormUI, AJAX, Bootstrap)
- `jq` or Python's json for parsing (handled internally)

## Future Enhancements

1. **Export functionality**: Download audit results as CSV/JSON
2. **Historical tracking**: Store audit snapshots over time
3. **Filtering**: Filter records by source, status, type
4. **Quick actions**: Inline buttons to clean specific records
5. **Metrics**: Graph of record counts over time
6. **Alerts**: Email notifications when issues are detected

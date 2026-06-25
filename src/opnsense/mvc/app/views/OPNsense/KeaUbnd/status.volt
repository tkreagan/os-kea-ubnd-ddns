{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Thomas Reagan
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<style>
    .kea-hostname { font-family: monospace; font-size: 0.9em; }
    .kea-ip       { font-family: monospace; font-size: 0.9em; }
    th.sortable   { cursor: pointer; user-select: none; white-space: nowrap; }
    th.sortable:after        { content: ' \2195'; opacity: 0.4; }
    th.sortable.asc:after    { content: ' \2191'; opacity: 1; }
    th.sortable.desc:after   { content: ' \2193'; opacity: 1; }
    .kea-summary td, .kea-summary th { vertical-align: middle; white-space: nowrap; border-top: none !important; padding: 3px 8px !important; }
    .kea-summary tr.kea-spacer-before td { padding-top: 12px !important; }
    .kea-summary tr.kea-spacer-after  td { padding-bottom: 12px !important; }
    /* Compact (content width) when explanations are hidden; full width with a
       wrapping description column when shown. */
    .kea-summary          { width: auto; }
    .kea-summary.kea-wide { width: 100%; }
    .kea-summary .kea-desc { white-space: normal; width: 100%; }
    /* Explicit blue — OPNsense's theme renders text-primary/label-primary orange. */
    .kea-blue            { color: #2c6fbb; }
    .label.label-kea-blue { background-color: #2c6fbb; }
    .kea-amber           { color: #c9890a; }
    .kea-flag            { text-align: center; }
    /* Let the boolean column headers wrap at spaces so the columns stay narrow. */
    th.sortable.kea-flag { white-space: normal; }
    /* Long IPv6 ip6.arpa reverse names: truncate with ellipsis; click to expand. */
    .kea-revname { display: inline-block; max-width: 26ch; overflow: hidden;
                   text-overflow: ellipsis; white-space: nowrap;
                   vertical-align: bottom; cursor: pointer; }
    .kea-revname.kea-expanded { max-width: none; white-space: normal; word-break: break-all; }
    /* OPNsense theme renders <code> crimson; override to neutral monospace. */
    .panel code { color: #555; background: none; }
    /* Collision group-header rows: relative overlay works on light and dark themes. */
    .ku-group-hdr, .ku-group-hdr td { background-color: rgba(128,128,128,0.12) !important; }
    /* Jump-to navigation links */
    .ku-jumpbar a { color: #5a9dd5; margin-right: 10px; font-size: 0.85em; }
    .ku-jumpbar a:hover { color: #337ab7; text-decoration: underline; }
    /* Purple for magic/synthetic records — collision disambiguation. */
    .kea-purple              { color: #7040a0; }
    .label.label-kea-purple  { background-color: #7040a0; }
</style>

<script>
// True until the first successful render; controls whether we show the full-page
// spinner or do a silent in-place update.
var auditInitialLoad = true;

function updateReadiness() {
    ajaxGet('/api/keaubnd/service/readiness', {}, function(data, status) {
        if (status !== 'success' || !data) { return; }
        const banners = {
            refused: ['danger',  'fa-circle-xmark',          'DDNS listener not started'],
            stopped: ['danger',  'fa-circle-xmark',          'DDNS listener stopped'],
            alert:   ['warning', 'fa-triangle-exclamation',  'DDNS listener degraded'],
            blocked: ['warning', 'fa-circle-nodes',          'Repopulating DNS after a Kea/Unbound restart'],
        };
        const b = banners[data.state];
        const $box = $('#keaubnd_readiness');
        if (!b) { $box.hide().empty(); return; }
        const detail = data.detail ? (' — ' + $('<div>').text(data.detail).html()) : '';
        $box.html('<div class="alert alert-' + b[0] + '" role="alert">' +
            '<i class="fa-solid ' + b[1] + '"></i> <b>' + b[2] + '</b>' + detail +
            '</div>').show();
    });
}

$( document ).ready(function() {
    loadAuditData();
    updateReadiness();
    setInterval(function() {
        if (!$("#autoRefreshCheck").is(":checked")) return;
        // Don't stomp on the user while they're typing into a filter box.
        var active = document.activeElement;
        if (active && (active.id === 'fwdSearchInput' || active.id === 'revSearchInput')) return;
        loadAuditData();
    }, 30000);
    setInterval(updateReadiness, 5000);

    $("#refreshBtn").click(function() { loadAuditData(); });

    $(document).on("click", "#toggleDesc", function(e) {
        e.preventDefault();
        showDesc = !showDesc;
        applyDescVisibility();
    });

    // Click a truncated (IPv6) reverse name to expand/collapse it.
    $(document).on("click", ".kea-revname", function() {
        $(this).toggleClass("kea-expanded");
    });

    $("#cleanBtn").click(function() {
        $("#cleanConfirmModal").modal("show");
    });

    $("#cleanConfirmBtn").click(function() {
        $("#cleanConfirmModal").modal("hide");
        const btn = $("#cleanBtn");
        btn.prop("disabled", true).html('<i class="fa fa-spinner fa-spin"></i> Cleaning...');
        ajaxCall("/api/keaubnd/general/clean", {}, function() {
            loadAuditData();
        });
    });

    // Manual sync buttons — force a re-sync from Kea, then refresh the audit.
    function triggerSync(btn, endpoint) {
        const orig = btn.html();
        btn.prop("disabled", true).html('<i class="fa fa-spinner fa-spin"></i> Syncing...');
        ajaxCall(endpoint, {}, function() {
            btn.prop("disabled", false).html(orig);
            loadAuditData();
        });
    }
    $("#syncBtn").click(function() { triggerSync($(this), "/api/keaubnd/general/sync_full"); });

    // Search inputs — delegated because the inputs are inside dynamically-rendered HTML.
    $(document).on("input", "#fwdSearchInput", function() {
        fwdSearch = $(this).val();
        applyFwdSearch(fwdSearch);
    });
    $(document).on("input", "#revSearchInput", function() {
        revSearch = $(this).val();
        applyRevSearch(revSearch);
    });

    // Sortable table
    $(document).on("click", "th.sortable", function() {
        const th = $(this);
        const table = th.closest("table");
        const col = th.index();
        const asc = !th.hasClass("asc");

        table.find("th.sortable").removeClass("asc desc");
        th.addClass(asc ? "asc" : "desc");

        const rows = table.find("tbody tr").toArray();
        rows.sort(function(a, b) {
            const cellA = $(a).children("td").eq(col);
            const cellB = $(b).children("td").eq(col);
            const va = cellA.data("sort") !== undefined ? String(cellA.data("sort")) : cellA.text().trim();
            const vb = cellB.data("sort") !== undefined ? String(cellB.data("sort")) : cellB.text().trim();
            return asc ? va.localeCompare(vb) : vb.localeCompare(va);
        });
        table.find("tbody").empty().append(rows);
    });
});

function loadAuditData() {
    if (auditInitialLoad) {
        // First load: show the spinner and hide content until data arrives.
        $("#statusLoader").show();
        $("#statusContent").hide();
    } else {
        // Subsequent refreshes: update in-place so the page doesn't jump.
        $("#refreshIndicator").show();
    }
    $("#statusError").hide();

    $.ajax({
        url: '/api/keaubnd/status/audit',
        type: 'GET',
        dataType: 'json',
        timeout: 15000,
        success: function(data) {
            if (data.status === 'error') { showError(data.message || 'Audit failed'); return; }
            if (!data.audit)             { showError('Invalid response from audit endpoint'); return; }
            renderAuditData(data.audit);
            $("#statusLoader").hide();
            $("#refreshIndicator").hide();
            $("#statusContent").show();
            auditInitialLoad = false;
        },
        error: function(xhr, status) {
            $("#refreshIndicator").hide();
            showError(status === 'timeout' ? 'Request timed out' : 'Failed to load audit data');
        }
    });
}

function showError(message) {
    $("#statusLoader").hide();
    $("#cleanBtn, #syncBtn").prop("disabled", true);
    $("#syncBtn").attr("title", "Kea is unavailable — sync cannot run");
    $("#statusError").html(
        '<div class="alert alert-danger alert-dismissible" role="alert">' +
        '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
        '<strong>Error:</strong> ' + escapeHtml(message) + '</div>'
    ).show();
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// Compute the expected .arpa PTR name for an IPv4 or IPv6 address.
function reversePtr(ip) {
    if (!ip) return '';
    if (ip.indexOf(':') >= 0) {
        // IPv6: expand all 8 groups to 4 hex digits, concatenate into 32 nibbles,
        // reverse, and join with dots.
        var halves = ip.split('::');
        var left  = halves[0] ? halves[0].split(':') : [];
        var right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
        while (left.length + right.length < 8) left.push('0');
        var groups = left.concat(right);
        var nibbles = groups.map(function(g) {
            return ('0000' + g).slice(-4);
        }).join('').split('').reverse().join('.');
        return nibbles + '.ip6.arpa';
    }
    // IPv4: reverse the dotted octets.
    return ip.split('.').reverse().join('.') + '.in-addr.arpa';
}

function flag(on, color) {
    // FontAwesome circles (filled = present, ring = absent) so these and the
    // PTR-state icons in the same row share one size and baseline.
    return '<i class="' + (on ? 'fa-solid fa-circle' : 'fa-regular fa-circle') +
           '" style="color:' + color + ';"></i>';
}

// Reservation column: filled blue = static IP reservation, half-filled = hostname-only.
function reservationFlag(r) {
    if (r.reserved) {
        return '<i class="fa-solid fa-circle" style="color:#2c6fbb;" title="Static IP reservation"></i>';
    }
    if (r.hostname_reserved) {
        return '<i class="fa-regular fa-circle-half-stroke" style="color:#2c6fbb;" title="Hostname-only reservation (dynamic IP)"></i>';
    }
    return '<i class="fa-regular fa-circle" style="color:#2c6fbb;"></i>';
}

// Per-host reverse (PTR) state icon.
function ptrIcon(state) {
    switch (state) {
        case 'correct':
            return '<i class="fa-solid fa-circle" style="color:#3c763d;" title="Reverse (PTR) points to this host"></i>';
        case 'multiple':
            return '<i class="fa-solid fa-circle-nodes" style="color:#c9890a;" title="This IP has multiple PTR records (one names this host)"></i>';
        case 'wrong':
            return '<i class="fa-regular fa-circle-xmark" style="color:#a94442;" title="This IP has a PTR, but none point to this host"></i>';
        default: // 'none'
            return '<i class="fa-regular fa-circle" style="color:#999;" title="No reverse (PTR) record for this IP"></i>';
    }
}

// Zero-pad each octet so IP addresses sort numerically rather than lexicographically.
function ipSortKey(ip) {
    if (!ip) return '';
    var parts = ip.split('.');
    if (parts.length === 4) return parts.map(function(p) { return p.padStart(3, '0'); }).join('.');
    return ip;
}

// Hostname sort key that groups magic records immediately after their original.
// Without this, 'foo-mAABBCC.domain' sorts before 'foo.domain' because
// hyphen (U+002D) < period (U+002E) in Unicode order.
function hostnameSort(r) {
    return r.is_magic ? (r.magic_for || r.hostname) + '￿' + r.hostname : r.hostname;
}

// Sort keys for icon columns — lower = "better" so ascending sorts best-first.
function ptrSortKey(state) {
    return {correct: '1', multiple: '2', wrong: '3', none: '4'}[state] || '4';
}
function fwdSortKey(state) {
    return {match: '1', partial: '2', mismatch: '3', orphan: '4'}[state] || '4';
}

// Forward-consistency icon for a PTR record.
function fwdIcon(state) {
    switch (state) {
        case 'match':
            return '<i class="fa-solid fa-circle" style="color:#3c763d;" title="Forward A/AAAA matches this PTR"></i>';
        case 'partial':
            return '<i class="fa-solid fa-circle" style="color:#c9890a;" title="Forward matches, but other names on this IP have no PTR"></i>';
        case 'mismatch':
            return '<i class="fa-solid fa-circle" style="color:#c9890a;" title="Forward A/AAAA points to a different IP"></i>';
        default: // 'orphan'
            return '<i class="fa-solid fa-circle" style="color:#a94442;" title="No forward A/AAAA record (orphan PTR)"></i>';
    }
}

// Wizard-hat icon for magic FQDN rows.
function magicHatIcon(idTag, source) {
    var tip = 'Magic hostname: id suffix ' + idTag + ', source: ' + source;
    return '<i class="fa-solid fa-hat-wizard kea-purple" title="' + escapeHtml(tip) + '"></i>';
}

// LAA (Locally Administered Address) indicator — suffix may rotate with MAC randomization.
function laaIcon() {
    return '<i class="fa-solid fa-house-circle-exclamation kea-purple" style="font-size:0.9em;" title="Locally Administered Address — this suffix may rotate if the device uses MAC randomization"></i>';
}

// Sparkles hint on original hostname rows that have a magic name for this IP.
function sparklesHint(magicFqdn) {
    return '<i class="fa-regular fa-hand-point-down kea-purple" style="font-size:0.85em;" title="Magic name: ' + escapeHtml(magicFqdn) + '"></i>';
}

// Whether the summary's "What it means" column is shown. Persists across the
// 30s auto-refresh re-renders; applied after each render.
var showDesc = false;
// Search state — persisted so values survive the 30s auto-refresh HTML replacement.
var fwdSearch = '';
var revSearch = '';

function applyFwdSearch(q) {
    var lq = q.toLowerCase();
    $(".kea-records tbody tr").each(function() {
        $(this).toggle(!lq || $(this).text().toLowerCase().indexOf(lq) >= 0);
    });
}
function applyRevSearch(q) {
    var lq = q.toLowerCase();
    $(".kea-ptrs tbody tr").each(function() {
        $(this).toggle(!lq || $(this).text().toLowerCase().indexOf(lq) >= 0);
    });
}
function applyDescVisibility() {
    $(".kea-desc").toggle(showDesc);
    $(".kea-summary").toggleClass("kea-wide", showDesc);
    $("#toggleDesc").text(showDesc ? "Hide explanations" : "Show explanations");
}

function renderAuditData(audit) {
    // Capture current search values before HTML is replaced.
    var $fwd = $('#fwdSearchInput');
    if ($fwd.length) fwdSearch = $fwd.val();
    var $rev = $('#revSearchInput');
    if ($rev.length) revSearch = $rev.val();

    const records = audit.records || [];
    const orphans  = audit.orphaned_ptrs || [];

    // Index magic records by lowercased FQDN for PTR target annotation.
    const magicByFqdn = {};
    records.filter(r => r.is_magic).forEach(function(r) {
        magicByFqdn[r.hostname.toLowerCase().replace(/\.$/, '')] = r;
    });

    // Sync buttons need Kea — disable them when the audit couldn't reach it.
    const syncOk = !!audit.complete;
    $("#syncBtn")
        .prop("disabled", !syncOk)
        .attr("title", syncOk ? "" : "Kea is unavailable — sync cannot run");

    // Authoritative counts for cleanup (status-based).
    const stale     = records.filter(r => r.status === 'stale').length;
    const orphanN   = orphans.length;
    const removable = stale + orphanN;

    // Summary counts for the Active Leases section form a partition:
    //   sLeaseOk + sMagic + sUnregistered + sCollisionNoMagic = sActiveLease
    // (sCollisionNoMagic is a transient edge case where the daemon hasn't yet
    //  generated magic records for a collision — not shown separately.)
    const sActiveLease   = records.filter(r => r.leased).length;
    const sLeaseOk       = records.filter(r => r.leased && (r.status === 'ok' || r.status === 'static')).length;
    const sConfigured    = records.filter(r => (r.reserved || r.override) && !r.leased).length;
    // missing-PTR: A/AAAA in Unbound but no PTR. Does not include unregistered or
    // collision entries — those have no forward record at all.
    const sMissingPtr    = records.filter(r => r.status === 'missing-PTR').length;
    // unregistered: active lease/reservation with no DNS record at all.
    const sUnregistered  = records.filter(r => r.status === 'unregistered').length;
    const sStaleOrphan   = stale + orphanN;
    const sUnknown       = records.filter(r => r.status === 'unknown').length;
    // Magic / collision counts.
    // magicIPs: set of IPs that have at least one synthetic magic hostname record.
    const magicIPs          = new Set(records.filter(r => r.is_magic).map(r => r.ip));
    // sMagic: collision-loser leases whose only DNS coverage is a magic name
    // (subset of Active Leases; mutually exclusive with sLeaseOk).
    const sMagic            = records.filter(r => r.leased && r.status === 'collision' && magicIPs.has(r.ip)).length;
    // sCollisionNames: unique contested hostnames (how many names are disputed).
    const sCollisionNames   = new Set(records.filter(r => r.status === 'collision').map(r => r.hostname)).size;
    // sMagicHosts: all leased hosts that received a magic record (winners + losers).
    const sMagicHosts       = new Set(records.filter(r => r.leased && magicIPs.has(r.ip)).map(r => r.ip)).size;
    // sCollisionNoMagic: collision-status leases with no magic coverage — gap in the
    // partition (occurs when magic_names is disabled and collision_policy != allow).
    const sCollisionNoMagic = records.filter(r => r.leased && r.status === 'collision' && !magicIPs.has(r.ip)).length;

    let html = '';

    // Kea unavailable warning
    if (!audit.complete && audit.kea_error) {
        html += '<div class="alert alert-warning alert-dismissible" role="alert">' +
                '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
                '<strong>Warning:</strong> DNS data is incomplete — Kea unavailable: ' +
                escapeHtml(audit.kea_error) + '</div>';
    }

    // ── Summary table ─────────────────────────────────────────────────────────
    const summaryRows = [
        ['Active Leases', 'text-success', sActiveLease,
         'A client currently holds this address — a dynamic lease, or a static reservation whose host is online. Registered in DNS with a lease-tracking TTL.'],
        ['↳ Directly Registered in DNS', 'text-success', sLeaseOk,
         'Active leases with both a forward (A/AAAA) and reverse (PTR) record present in Unbound. Subset of Active Leases above.'],
    ];
    if (sMagic > 0) {
        summaryRows.push(['↳ Registered via Magic Hostname Only', 'kea-purple', sMagic,
            'Active leases whose only DNS entry is a synthetic magic hostname — the original name was won by another device. ' +
            'Each gets a disambiguated name encoding its hardware identifier suffix ' +
            '(e.g. <code>laptop-mAABBCC.home.lan</code>). Persist until the backing lease expires. ' +
            'See the Hostname Collisions section below.']);
    }
    if (sCollisionNoMagic > 0) {
        summaryRows.push(['↳ No DNS Coverage', 'kea-amber', sCollisionNoMagic,
            'Active leases displaced by a hostname collision with no magic hostname to fall back on — completely absent from DNS. ' +
            'Enable Magic Hostname Records in Settings, or switch the collision policy to <strong>allow</strong>.']);
    }
    if (sUnregistered > 0) {
        summaryRows.push(['↳ Unregistered', 'kea-amber', sUnregistered,
            'Active lease not registered in DNS. May be blocked by a host override for the same hostname, or the DDNS update may not have been sent or processed yet.']);
    }
    summaryRows.push(
        ['Static Reservations & Host Overrides', 'kea-blue', sConfigured,
         'Configured but not currently leased: a Kea reservation with no active lease yet, or an Unbound host override. Resolves whether or not a client is online.', 'kea-spacer-before kea-spacer-after'],
        ['Missing PTR', 'kea-amber', sMissingPtr,
         'A/AAAA record is in Unbound but has no matching reverse (PTR) record. Counts across the rows above.'],
        ['Hostnames w/Collision', 'kea-amber', sCollisionNames,
         'Number of distinct hostnames currently contested by two or more active devices under the current collision policy (first_wins / last_wins / none). Switch the collision policy to <strong>allow</strong> to register all devices under their original name.'],
    );
    if (sMagicHosts > 0 && sCollisionNames > 0) {
        summaryRows.push(['↳ Magic Hostname Records', 'kea-purple', sMagicHosts,
            'Hosts across all collision groups that received a synthetic magic hostname — includes both the winner (registered under the original name) and all losers.']);
    }
    summaryRows.push(
        ['Possibly Stale / Orphaned', 'text-danger', sStaleOrphan,
         'A record in Unbound not backed by any active lease, Kea reservation, or configured host override — or a reverse (PTR) with no forward record. May be removable.' +
         '<br><br>These are not necessarily wrong: they are simply not backed by Kea or an Unbound host override (for example, left over from an expired lease, or a record added by another tool). Cleaning removes them; anything still in use re-registers on the next lease renewal or sync.']
    );
    if (sUnknown > 0) {
        summaryRows.push(['Undetermined', 'text-muted', sUnknown,
            'Kea data is unavailable, so backing cannot be determined right now.']);
    }
    html += '<div id="ku-summary" class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading">' +
            '<h4 class="panel-title" style="display:inline;">Summary</h4>' +
            '<span style="float:right; display:inline-flex; align-items:center; gap:12px;">' +
            '<a href="#" id="toggleDesc" class="small"></a>' +
            '<a href="#ku-top" class="small" style="color:#aaa;">&#x2191; top</a>' +
            '</span>' +
            '</div>' +
            '<div class="panel-body" style="padding:0;">' +
            '<table class="table table-condensed kea-summary" style="margin-bottom:0;">' +
            '<thead><tr><th>Category</th><th class="text-right">Count</th><th class="kea-desc">What it means</th></tr></thead><tbody>';
    summaryRows.forEach(function(r) {
        html += '<tr' + (r[4] ? ' class="' + r[4] + '"' : '') + '>' +
            '<td><span class="' + r[1] + '"><strong>' + r[0] + '</strong></span></td>' +
            '<td class="text-right ' + r[1] + '"><strong>' + r[2] + '</strong></td>' +
            '<td class="text-muted kea-desc">' + r[3] + '</td>' +
            '</tr>';
    });
    html += '</tbody></table></div></div>';

    // ── Static Reservations & Config Overrides detail ────────────────────────
    // Show ALL reserved/override entries regardless of lease state. Sort: active
    // leases first (device online), then offline entries, both alpha within group.
    const configuredRecs = records.filter(function(r) {
        return r.reserved || r.override;
    }).sort(function(a, b) {
        if (a.leased !== b.leased) return a.leased ? -1 : 1;
        return hostnameSort(a).localeCompare(hostnameSort(b));
    });

    html += '<div id="ku-configured" class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
            '<h4 class="panel-title" style="margin:0;">Static Reservations &amp; Host Overrides</h4>' +
            '<a href="#ku-top" class="small" style="color:#aaa;">&#x2191; top</a>' +
            '</div>';
    if (configuredRecs.length === 0) {
        html += '<div class="panel-body">' +
                '<p class="text-muted" style="margin:0;">' +
                'No static reservations or host overrides are configured.</p>' +
                '</div>';
    } else {
        html += '<div class="panel-body" style="padding:0 0 8px;">' +
                '<p class="text-muted" style="padding:8px 12px 4px; margin:0;">' +
                'All Kea static reservations and Unbound host overrides. ' +
                'These entries resolve in DNS whether or not a client is currently online. ' +
                '<strong>Static Res.</strong> = defined in the Kea config and synced to Unbound. ' +
                '<strong>Override</strong> = entry in Unbound host overrides with no corresponding Kea reservation.' +
                '</p>' +
                '<div class="table-responsive">' +
                '<table class="table table-condensed table-striped" style="margin:0;">' +
                '<thead><tr>' +
                '<th>Hostname</th>' +
                '<th>IP Address</th>' +
                '<th>Status</th>' +
                '<th>Type</th>' +
                '<th>Identifier</th>' +
                '</tr></thead><tbody>';
        configuredRecs.forEach(function(r) {
            var typeLabel;
            if (r.reserved && r.override) {
                typeLabel = 'Static Res. &amp; Override';
            } else if (r.reserved) {
                typeLabel = 'Static Res.';
            } else {
                typeLabel = 'Override';
            }
            var ident = r.identifier || {};
            var identCell = ident.value
                ? '<span class="text-muted" style="font-size:0.85em;">' + escapeHtml(ident.type) + '</span> ' +
                  '<span style="font-family:monospace; font-size:0.9em;">' + escapeHtml(ident.value) + '</span>'
                : '<span class="text-muted">—</span>';
            var statusCell;
            if (r.leased && r.live) {
                statusCell = '<span class="text-success">Active lease &middot; DNS live</span>';
            } else if (r.leased && !r.live) {
                statusCell = '<span class="kea-amber">Active lease &middot; not in DNS</span>';
            } else if (!r.leased && r.live) {
                statusCell = '<span class="kea-blue">No lease &middot; DNS live</span>';
            } else {
                statusCell = '<span class="text-muted">No lease &middot; no DNS record</span>';
            }
            html += '<tr>' +
                '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                '<td class="kea-ip"><span class="kea-revname" title="' + escapeHtml(r.ip) + '">' + escapeHtml(r.ip) + '</span></td>' +
                '<td>' + statusCell + '</td>' +
                '<td>' + typeLabel + '</td>' +
                '<td>' + identCell + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div></div>';
    }
    html += '</div>';

    // ── Hostname Collisions panel ─────────────────────────────────────────────
    // Group all leased non-magic records by hostname; keep groups with >1 unique IP.
    // This works across all collision policies: allow mode shows all as Registered,
    // last_wins/first_wins shows winner (ok) + displaced (collision),
    // none shows all as Displaced (all evicted).
    const missingPtr    = records.filter(function(r) { return r.status === 'missing-PTR'; })
                                 .sort(function(a, b) { return hostnameSort(a).localeCompare(hostnameSort(b)); });
    const unregistered  = records.filter(function(r) { return r.status === 'unregistered'; })
                                 .sort(function(a, b) { return hostnameSort(a).localeCompare(hostnameSort(b)); });

    // Split unregistered into override-blocked vs genuinely unregistered.
    // A lease is override-blocked when the same hostname has a host override in
    // Unbound — the daemon intentionally skips DDNS updates for those names.
    const overrideHostnames = new Set(records.filter(function(r) { return r.override; }).map(function(r) { return r.hostname; }));
    const hostOverrideBlocked   = unregistered.filter(function(r) { return overrideHostnames.has(r.hostname); });
    const genuinelyUnregistered = unregistered.filter(function(r) { return !overrideHostnames.has(r.hostname); });

    const leasesByHostname = {};
    records.filter(r => r.leased && !r.is_magic).forEach(function(r) {
        if (!leasesByHostname[r.hostname]) leasesByHostname[r.hostname] = [];
        leasesByHostname[r.hostname].push(r);
    });
    const collisionGroups = Object.entries(leasesByHostname)
        .filter(function([hn, recs]) { return new Set(recs.map(r => r.ip)).size > 1; })
        .map(function([hn, recs]) { return { hostname: hn, records: recs }; })
        .sort(function(a, b) { return a.hostname.localeCompare(b.hostname); });

    if (collisionGroups.length > 0) {
        const magicFqdnByKey = {};
        records.forEach(function(r) {
            if (r.magic_fqdn) {
                magicFqdnByKey[r.hostname.toLowerCase() + '/' + r.ip] = r.magic_fqdn;
            }
        });
        const hasMagic = Object.keys(magicFqdnByKey).length > 0;
        const colSpan  = hasMagic ? '5' : '4';
        const policy   = audit.collision_policy || '—';
        const allRegistered = collisionGroups.every(function(g) {
            return g.records.every(function(r) { return r.status === 'ok' || r.status === 'static'; });
        });
        const collisionDesc = allRegistered
            ? 'All devices in each group are registered in DNS — multiple A records resolve to this hostname (round-robin).'
            : 'One or more devices in each group are displaced from DNS because another device holds the same hostname.' +
              (hasMagic ? ' Magic hostnames give each device a stable disambiguated name.' : '');

        html += '<div id="ku-collisions" class="panel panel-default" style="margin-bottom:16px;">' +
                '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
                '<h4 class="panel-title" style="margin:0;">Hostname Collisions</h4>' +
                '<a href="#ku-top" class="small" style="color:#aaa;">&#x2191; top</a>' +
                '</div>' +
                '<div class="panel-body" style="padding:0;">' +
                '<div style="padding:10px 12px 4px; display:flex; align-items:baseline; gap:8px;">' +
                '<span class="' + (allRegistered ? 'text-success' : 'kea-amber') + '" style="font-weight:600;">' +
                collisionGroups.length + ' hostname' + (collisionGroups.length !== 1 ? 's' : '') + '</span>' +
                '<span class="text-muted" style="font-size:0.88em;">policy: ' + escapeHtml(policy) + '</span>' +
                '</div>' +
                '<p class="text-muted" style="padding:0 12px 8px; margin:0; font-size:0.9em;">' + collisionDesc + '</p>' +
                '<div class="table-responsive">' +
                '<table class="table table-condensed" style="margin:0;">' +
                '<thead><tr>' +
                '<th>Status</th><th>Hostname</th><th>IP Address</th><th>Type</th>' +
                (hasMagic ? '<th>Magic Name</th>' : '') +
                '</tr></thead><tbody>';
        collisionGroups.forEach(function(group) {
            const sorted = group.records.slice().sort(function(a, b) {
                if (a.status === b.status) return a.ip.localeCompare(b.ip);
                return (a.status === 'ok' || a.status === 'static') ? -1 : 1;
            });
            html += '<tr class="ku-group-hdr">' +
                '<td colspan="' + colSpan + '" style="padding:4px 8px; font-size:0.85em; color:#888; border-top:1px solid #ddd;">' +
                '<strong class="kea-hostname">' + escapeHtml(group.hostname) + '</strong>' +
                ' &ensp;' + sorted.length + ' device' + (sorted.length !== 1 ? 's' : '') +
                '</td></tr>';
            sorted.forEach(function(r) {
                const mf = magicFqdnByKey[r.hostname.toLowerCase() + '/' + r.ip] || '';
                const isReg = r.status === 'ok' || r.status === 'static';
                const roleHtml = isReg
                    ? '<span class="text-success">Registered <i class="fa fa-check"></i></span>'
                    : '<span class="kea-amber">Displaced</span>';
                html += '<tr>' +
                    '<td>' + roleHtml + '</td>' +
                    '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                    '<td class="kea-ip">' + escapeHtml(r.ip) + '</td>' +
                    '<td>' + escapeHtml(r.type) + '</td>' +
                    (hasMagic ? '<td class="kea-hostname kea-purple">' + (mf ? escapeHtml(mf) : '<span class="text-muted">—</span>') + '</td>' : '') +
                    '</tr>';
            });
        });
        html += '</tbody></table></div></div></div>';
    }

    // ── Other DNS Issues panel ────────────────────────────────────────────────
    const anyOtherIssues = missingPtr.length > 0 || hostOverrideBlocked.length > 0 || genuinelyUnregistered.length > 0;

    html += '<div id="ku-issues" class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
            '<h4 class="panel-title" style="margin:0;">Other DNS Issues</h4>' +
            '<a href="#ku-top" class="small" style="color:#aaa;">&#x2191; top</a>' +
            '</div>' +
            '<div class="panel-body"' + (anyOtherIssues ? ' style="padding:0;"' : '') + '>';

    if (!anyOtherIssues) {
        html += '<p class="text-success" style="margin:0;">' +
                '<i class="fa fa-check-circle"></i> No other DNS issues detected.</p>';
    } else {

        // ── Missing PTR ──────────────────────────────────────────────────────
        if (missingPtr.length > 0) {
            html += '<div style="padding:10px 12px 4px; display:flex; align-items:baseline; gap:8px;">' +
                    '<strong>Missing PTR</strong>' +
                    '<span class="kea-amber" style="font-weight:600;">' + missingPtr.length + '</span>' +
                    '</div>' +
                    '<p class="text-muted" style="padding:0 12px 6px; margin:0; font-size:0.9em;">' +
                    'A/AAAA record is in Unbound but has no matching reverse (PTR). ' +
                    'Reverse lookups — used by SSH known-hosts, syslog, and network tools — will fail for these addresses.' +
                    '</p>' +
                    '<div class="table-responsive" style="margin-bottom:12px;">' +
                    '<table class="table table-condensed table-striped" style="margin:0;">' +
                    '<thead><tr><th>Hostname</th><th>IP Address</th><th>Type</th><th>PTR Expected</th></tr></thead><tbody>';
            missingPtr.forEach(function(r) {
                html += '<tr>' +
                    '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                    '<td class="kea-ip">'       + escapeHtml(r.ip)       + '</td>' +
                    '<td>' + escapeHtml(r.type) + '</td>' +
                    '<td class="kea-hostname">' + escapeHtml(reversePtr(r.ip)) + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // ── Blocked by Host Override ─────────────────────────────────────────
        if (hostOverrideBlocked.length > 0) {
            html += '<div style="padding:10px 12px 4px; display:flex; align-items:baseline; gap:8px;">' +
                    '<strong>Blocked by Host Override</strong>' +
                    '<span class="kea-amber" style="font-weight:600;">' + hostOverrideBlocked.length + '</span>' +
                    '</div>' +
                    '<p class="text-muted" style="padding:0 12px 6px; margin:0; font-size:0.9em;">' +
                    'Active lease not registered in DNS because the hostname is managed by a host override. ' +
                    'The daemon skips DDNS updates for names defined in Unbound host overrides to avoid overwriting static entries. ' +
                    'To add a DNS record for this lease, add a matching entry to the host override in Unbound settings.' +
                    '</p>' +
                    '<div class="table-responsive" style="margin-bottom:12px;">' +
                    '<table class="table table-condensed table-striped" style="margin:0;">' +
                    '<thead><tr><th>Hostname</th><th>IP Address</th><th>Type</th></tr></thead><tbody>';
            hostOverrideBlocked.forEach(function(r) {
                html += '<tr>' +
                    '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                    '<td class="kea-ip">'       + escapeHtml(r.ip)       + '</td>' +
                    '<td>' + escapeHtml(r.type) + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // ── Unregistered Lease ───────────────────────────────────────────────
        if (genuinelyUnregistered.length > 0) {
            html += '<div style="padding:10px 12px 4px; display:flex; align-items:baseline; gap:8px;">' +
                    '<strong>Unregistered Lease</strong>' +
                    '<span class="kea-amber" style="font-weight:600;">' + genuinelyUnregistered.length + '</span>' +
                    '</div>' +
                    '<p class="text-muted" style="padding:0 12px 6px; margin:0; font-size:0.9em;">' +
                    'Active lease with no DNS record — no A/AAAA and no PTR. ' +
                    'The DDNS update may not have been sent or processed yet, or the daemon was not running when the lease was issued.' +
                    '</p>' +
                    '<div class="table-responsive" style="margin-bottom:12px;">' +
                    '<table class="table table-condensed table-striped" style="margin:0;">' +
                    '<thead><tr><th>Hostname</th><th>IP Address</th><th>Type</th></tr></thead><tbody>';
            genuinelyUnregistered.forEach(function(r) {
                html += '<tr>' +
                    '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                    '<td class="kea-ip">'       + escapeHtml(r.ip)       + '</td>' +
                    '<td>' + escapeHtml(r.type) + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }
    }

    html += '</div></div>';

    // ── Stale / cleanup section ───────────────────────────────────────────────
    html += '<div id="ku-cleanup" class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
            '<h4 class="panel-title" style="margin:0;">Stale Records</h4>' +
            '<a href="#ku-top" class="small" style="color:#aaa;">&#x2191; top</a>' +
            '</div>' +
            '<div class="panel-body">';

    if (!audit.complete) {
        html += '<p class="text-muted">Cleanup unavailable — Kea data is required to safely identify stale records.</p>';
        updateCleanButton(false, 0);
    } else if (removable === 0) {
        html += '<p class="text-success"><i class="fa fa-check-circle"></i> No stale or orphaned records found.</p>';
        updateCleanButton(true, 0);
    } else {
        html += '<p class="text-warning"><i class="fa fa-exclamation-triangle"></i> ' + removable + ' record(s) can be removed: ' +
                stale + ' possibly-stale record' + (stale !== 1 ? 's' : '') +
                (orphanN > 0 ? ', ' + orphanN + ' possible orphan PTR' + (orphanN !== 1 ? 's' : '') : '') + '.</p>';
        updateCleanButton(true, removable);

        // Detail the stale forward records that will be removed.
        if (stale > 0) {
            const staleRecs = records.filter(r => r.status === 'stale')
                .sort((a, b) => a.hostname.localeCompare(b.hostname));
            html += '<p class="text-muted" style="margin-bottom:4px;"><strong>Possibly stale records:</strong></p>';
            html += '<table class="table table-condensed" style="margin-bottom:12px;"><thead><tr>' +
                    '<th>Hostname</th><th>Type</th><th>IP Address</th><th>TTL</th><th>Source</th>' +
                    '</tr></thead><tbody>';
            staleRecs.forEach(function(r) {
                html += '<tr>' +
                    '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                    '<td>' + escapeHtml(r.type) + '</td>' +
                    '<td class="kea-ip">'       + escapeHtml(r.ip)   + '</td>' +
                    '<td>' + escapeHtml(r.ttl != null ? String(r.ttl) : '—') + '</td>' +
                    '<td>' + escapeHtml(r.source) + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table>';
        }
        // Detail the orphaned PTR records that will be removed.
        if (orphanN > 0) {
            html += '<p class="text-muted" style="margin-bottom:4px;"><strong>Possible orphan PTR records:</strong></p>';
            html += '<table class="table table-condensed" style="margin-bottom:0;"><thead><tr>' +
                    '<th>PTR Name</th><th>Address</th><th>Type</th><th>TTL</th><th>Points To</th>' +
                    '</tr></thead><tbody>';
            orphans.forEach(function(o) {
                html += '<tr>' +
                    '<td class="kea-hostname">' + escapeHtml(o.ptr_name) + '</td>' +
                    '<td class="kea-ip">' + escapeHtml(o.address ? o.address : '—') + '</td>' +
                    '<td>PTR</td>' +
                    '<td>' + escapeHtml(o.ttl != null ? String(o.ttl) : '—') + '</td>' +
                    '<td class="kea-hostname">' + escapeHtml(o.target ? o.target : '—') + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table>';
        }
    }
    html += '</div></div>';

    // ── DNS records table ─────────────────────────────────────────────────────
    const liveRecords = records.filter(function(r) { return r.live || r.is_magic; });
    if (records.length > 0) {
        html += '<div id="ku-records" class="panel panel-default">' +
                '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
                '<h4 class="panel-title" style="margin:0;">DNS Records (' + liveRecords.length + ')</h4>' +
                '<span style="display:inline-flex;align-items:center;gap:8px;">' +
                '<input type="text" id="fwdSearchInput" placeholder="Filter…" class="form-control input-sm" style="width:160px;" value="' + escapeHtml(fwdSearch) + '">' +
                '<a href="#ku-top" class="small" style="color:#aaa;white-space:nowrap;">&#x2191; top</a>' +
                '</span>' +
                '</div>' +
                '<div class="panel-body" style="padding:0;">' +
                '<div class="table-responsive">' +
                '<table class="table table-striped table-condensed kea-records" style="margin:0;">' +
                '<thead><tr>' +
                '<th class="sortable">Hostname</th>' +
                '<th class="sortable">IP Address</th>' +
                '<th class="sortable">Type</th>' +
                '<th class="sortable">TTL</th>' +
                '<th class="sortable kea-flag">PTR</th>' +
                '<th class="sortable kea-flag">Active Lease</th>' +
                '<th class="sortable kea-flag">Reservation</th>' +
                '<th class="sortable kea-flag">Config Override</th>' +
                '</tr></thead><tbody>';

        // Show only records that are actually in DNS (live), plus magic records
        // (which are live by definition). Collision losers and unregistered entries
        // are covered by the DNS Issues panel — no need to repeat them here.
        records.filter(function(r) { return r.live || r.is_magic; }).forEach(function(r) {
            var hnCell;
            if (r.is_magic) {
                hnCell = '<span class="kea-hostname">' + escapeHtml(r.hostname) + '</span> ' +
                         magicHatIcon(r.magic_id_tag || '', r.magic_source || '') +
                         (r.magic_laa ? ' ' + laaIcon() : '') +
                         '<br><small class="text-muted" style="font-size:0.8em;">↳ ' + escapeHtml(r.magic_for || '') + '</small>';
            } else if (r.magic_fqdn) {
                hnCell = '<span class="kea-hostname">' + escapeHtml(r.hostname) + '</span> ' + sparklesHint(r.magic_fqdn);
            } else {
                hnCell = '<span class="kea-hostname">' + escapeHtml(r.hostname) + '</span>';
            }
            html += '<tr>' +
                '<td data-sort="' + escapeHtml(hostnameSort(r)) + '">' + hnCell + '</td>' +
                '<td class="kea-ip" data-sort="' + escapeHtml(ipSortKey(r.ip || '')) + '"><span class="kea-revname" title="' + escapeHtml(r.ip) + '">' + escapeHtml(r.ip) + '</span></td>' +
                '<td>' + escapeHtml(r.type) + '</td>' +
                '<td>' + escapeHtml(r.ttl != null ? String(r.ttl) : '—') + '</td>' +
                '<td class="kea-flag" data-sort="' + ptrSortKey(r.ptr_state) + '">' + ptrIcon(r.ptr_state) + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.leased   ? '1' : '0') + '">' + flag(r.leased,   '#3c763d') + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.reserved ? '2' : r.hostname_reserved ? '1' : '0') + '">' + reservationFlag(r) + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.override ? '1' : '0') + '">' + flag(r.override, '#2c6fbb') + '</td>' +
                '</tr>';
        });

        html += '</tbody></table></div>' +
                '<div class="panel-body" style="padding:6px 12px 8px;">' +
                '<span class="text-muted small">' +
                'PTR:&nbsp;&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#3c763d;"></i> correct&nbsp;&nbsp;' +
                '<i class="fa-solid fa-circle-nodes" style="color:#c9890a;"></i> multiple (one matches)&nbsp;&nbsp;' +
                '<i class="fa-regular fa-circle-xmark" style="color:#a94442;"></i> wrong (IP has a PTR, none name this host)&nbsp;&nbsp;' +
                '<i class="fa-regular fa-circle" style="color:#999;"></i> none' +
                '</span>' +
                '<br><span class="text-muted small">' +
                'Flags:&nbsp;&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#3c763d;"></i> yes&nbsp;' +
                '<i class="fa-regular fa-circle" style="color:#3c763d;"></i> no&nbsp;&mdash; green = active lease / live record&nbsp;&nbsp;' +
                'Reservation:&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#2c6fbb;"></i> static IP&nbsp;&nbsp;' +
                '<i class="fa-regular fa-circle-half-stroke" style="color:#2c6fbb;"></i> hostname-only (dynamic IP)&nbsp;&nbsp;' +
                '<i class="fa-regular fa-circle" style="color:#2c6fbb;"></i> none&nbsp;&nbsp;&nbsp;&nbsp;' +
                'Config override:&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#2c6fbb;"></i> yes&nbsp;' +
                '<i class="fa-regular fa-circle" style="color:#2c6fbb;"></i> no' +
                '</span>' +
                '<br><span class="text-muted small">' +
                'Magic:&nbsp;&nbsp;' +
                '<i class="fa-solid fa-hat-wizard kea-purple"></i> magic hostname&nbsp;&nbsp;' +
                '<i class="fa-solid fa-house-circle-exclamation kea-purple"></i> locally administered address (suffix may rotate)&nbsp;&nbsp;' +
                '<i class="fa-regular fa-hand-point-down kea-purple"></i> original hostname has a magic name' +
                '</span></div></div>';
    } else {
        html += '<div class="alert alert-info">No DNS records found.</div>';
    }

    // ── Reverse (PTR) records table ────────────────────────────────────────────
    const ptrs = audit.ptr_records || [];
    if (ptrs.length > 0) {
        html += '<div id="ku-ptrs" class="panel panel-default">' +
                '<div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">' +
                '<h4 class="panel-title" style="margin:0;">Reverse (PTR) Records (' + ptrs.length + ')</h4>' +
                '<span style="display:inline-flex;align-items:center;gap:8px;">' +
                '<input type="text" id="revSearchInput" placeholder="Filter…" class="form-control input-sm" style="width:160px;" value="' + escapeHtml(revSearch) + '">' +
                '<a href="#ku-top" class="small" style="color:#aaa;white-space:nowrap;">&#x2191; top</a>' +
                '</span>' +
                '</div>' +
                '<div class="panel-body" style="padding:0;">' +
                '<div class="table-responsive">' +
                '<table class="table table-striped table-condensed kea-ptrs" style="margin:0;">' +
                '<thead><tr>' +
                '<th class="sortable">IP Address</th>' +
                '<th class="sortable">Reverse Name</th>' +
                '<th class="sortable">Points To</th>' +
                '<th class="sortable">TTL</th>' +
                '</tr></thead><tbody>';
        ptrs.forEach(function(p) {
            const tgts = p.targets || [];
            const pts = tgts.map(function(t) {
                const magicRec = magicByFqdn[(t.target || '').toLowerCase().replace(/\.$/, '')];
                const mIcon = magicRec
                    ? ' ' + magicHatIcon(magicRec.magic_id_tag || '', magicRec.magic_source || '')
                    : '';
                return '<div>' + fwdIcon(t.fwd_state) + ' ' + escapeHtml(t.target) + mIcon + '</div>';
            }).join('');
            const ttls = tgts.map(function(t) {
                return '<div>' + escapeHtml(t.ttl != null ? String(t.ttl) : '—') + '</div>';
            }).join('');
            const worstFwd = tgts.reduce(function(w, t) {
                const k = fwdSortKey(t.fwd_state); return k > w ? k : w;
            }, '0');
            html += '<tr>' +
                '<td class="kea-ip" data-sort="' + escapeHtml(ipSortKey(p.ip || '')) + '">' + escapeHtml(p.ip ? p.ip : '—') + '</td>' +
                '<td><span class="kea-hostname kea-revname" title="' + escapeHtml(p.ptr_name) + '">' + escapeHtml(p.ptr_name) + '</span></td>' +
                '<td class="kea-hostname" data-sort="' + worstFwd + '">' + pts + '</td>' +
                '<td>' + ttls + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div>' +
                '<div class="panel-body" style="padding:6px 12px;">' +
                '<span class="text-muted small">Forward: ' +
                '<i class="fa-solid fa-circle" style="color:#3c763d;"></i> matches&nbsp;&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#c9890a;"></i> different IP, or other names on this IP lack a PTR&nbsp;&nbsp;' +
                '<i class="fa-solid fa-circle" style="color:#a94442;"></i> no forward record (orphan)' +
                '</span></div></div>';
    }

    $("#statusContent").html(html);
    applyDescVisibility();
    if (fwdSearch) { $('#fwdSearchInput').val(fwdSearch); applyFwdSearch(fwdSearch); }
    if (revSearch) { $('#revSearchInput').val(revSearch); applyRevSearch(revSearch); }
}

function updateCleanButton(complete, removable) {
    const btn  = $("#cleanBtn");
    const info = $("#cleanInfo");
    if (!complete) {
        btn.prop("disabled", true).html('<i class="fa fa-trash-o"></i> Clean Stale Records');
    } else if (removable === 0) {
        btn.prop("disabled", true).html('<i class="fa fa-trash-o"></i> Clean Stale Records');
    } else {
        btn.prop("disabled", false).html('<i class="fa fa-trash-o"></i> Clean ' + removable + ' Record' + (removable !== 1 ? 's' : '') + ' Now');
    }
}
</script>

<div class="modal fade" id="cleanConfirmModal" tabindex="-1" role="dialog" aria-labelledby="cleanConfirmModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="cleanConfirmModalLabel">Clean Stale Records</h4>
            </div>
            <div class="modal-body">
                <p>Remove stale and orphaned DNS records from Unbound?</p>
                <p class="text-muted">The stale set is recomputed server-side before removal. Records still in use will re-register on the next lease renewal or sync.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-warning" id="cleanConfirmBtn">
                    <i class="fa fa-trash-o"></i> Clean Records
                </button>
            </div>
        </div>
    </div>
</div>

<div id="keaubnd_readiness" style="display:none; margin-bottom:6px;"></div>
<a id="ku-top"></a>
<p class="small" style="padding:8px 15px 0; margin:0 0 8px; color:#777;">
    Compares Unbound's runtime DNS records against Kea leases, reservations, and
    Unbound Host Overrides. Records backed by an active source show as live; records
    with no backing can be removed with the Clean button. Use the Sync buttons to
    force a re-sync from Kea without restarting any service.
</p>
<div style="padding:4px 15px 8px; display:flex; align-items:center; justify-content:space-between;">
    <div>
        <button id="syncBtn" class="btn btn-default btn-xs">
            <i class="fa fa-download"></i> Sync All Leases
        </button>
        <button id="cleanBtn" class="btn btn-default btn-xs" disabled style="margin-left:4px;">
            <i class="fa fa-trash-o"></i> Clean Stale Records
        </button>
    </div>
    <span style="color:#777; display:inline-flex; align-items:center; gap:8px;">
        <i id="refreshIndicator" class="fa fa-refresh fa-spin" style="display:none; color:#aaa;"></i>
        <label style="margin:0; font-weight:normal; cursor:pointer; display:inline-flex; align-items:center; gap:4px;">
            <input type="checkbox" id="autoRefreshCheck" checked style="margin:0;">
            Auto-refresh
        </label>
        <button id="refreshBtn" class="btn btn-default btn-xs">
            <i class="fa fa-refresh"></i> Refresh Now
        </button>
    </span>
</div>

<div class="ku-jumpbar" style="padding:2px 15px 8px; border-bottom:1px solid #eee; margin-bottom:4px;">
    <span class="text-muted" style="font-size:0.85em; margin-right:4px;">Jump to:</span>
    <a href="#ku-summary">Summary</a>
    <a href="#ku-configured">Static &amp; Host Overrides</a>
    <a href="#ku-collisions">Hostname Collisions</a>
    <a href="#ku-issues">Other DNS Issues</a>
    <a href="#ku-cleanup">Stale Records</a>
    <a href="#ku-records">DNS Records</a>
    <a href="#ku-ptrs">PTR Records</a>
</div>

<div id="statusLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading DNS registration status...</p>
</div>

<div id="statusError"  style="display:none; padding:10px;"></div>
<div id="statusContent" style="display:none; padding:10px;"></div>
</content>

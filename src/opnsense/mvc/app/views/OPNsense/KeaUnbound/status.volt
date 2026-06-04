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
    .kea-summary td, .kea-summary th { vertical-align: middle; white-space: nowrap; }
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
</style>

<script>
$( document ).ready(function() {
    loadAuditData();
    setInterval(function() {
        if ($("#autoRefreshCheck").is(":checked")) { loadAuditData(); }
    }, 30000);

    // Only show a manual sync button if that sync is enabled in settings.
    $.ajax({ url: '/api/keaunbound/general/get', type: 'GET', dataType: 'json' }).done(function(d) {
        const g = (d && d.general && d.general.general) || {};
        if (String(g.sync_static_reservations) === '1') { $("#syncStaticBtn").show(); }
        if (String(g.sync_dynamic_leases) === '1')      { $("#syncDynamicBtn").show(); }
    });

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
        ajaxCall("/api/keaunbound/general/clean", {}, function() {
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
    $("#syncStaticBtn").click(function()  { triggerSync($(this), "/api/keaunbound/general/sync_static"); });
    $("#syncDynamicBtn").click(function() { triggerSync($(this), "/api/keaunbound/general/sync_dynamic"); });

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
    $("#statusLoader").show();
    $("#statusContent").hide();
    $("#statusError").hide();

    $.ajax({
        url: '/api/keaunbound/status/audit',
        type: 'GET',
        dataType: 'json',
        timeout: 15000,
        success: function(data) {
            if (data.status === 'error') { showError(data.message || 'Audit failed'); return; }
            if (!data.audit)             { showError('Invalid response from audit endpoint'); return; }
            renderAuditData(data.audit);
            $("#statusLoader").hide();
            $("#statusContent").show();
        },
        error: function(xhr, status) {
            showError(status === 'timeout' ? 'Request timed out' : 'Failed to load audit data');
        }
    });
}

function showError(message) {
    $("#statusLoader").hide();
    $("#cleanBtn").prop("disabled", true);
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

function flag(on, color) {
    // FontAwesome circles (filled = present, ring = absent) so these and the
    // PTR-state icons in the same row share one size and baseline.
    return '<i class="' + (on ? 'fa-solid fa-circle' : 'fa-regular fa-circle') +
           '" style="color:' + color + ';"></i>';
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

// Whether the summary's "What it means" column is shown. Persists across the
// 30s auto-refresh re-renders; applied after each render.
var showDesc = false;
function applyDescVisibility() {
    $(".kea-desc").toggle(showDesc);
    $(".kea-summary").toggleClass("kea-wide", showDesc);
    $("#toggleDesc").text(showDesc ? "Hide explanations" : "Show explanations");
}

function renderAuditData(audit) {
    const records = audit.records || [];
    const orphans  = audit.orphaned_ptrs || [];

    // Authoritative counts for cleanup (status-based).
    const stale     = records.filter(r => r.status === 'stale').length;
    const orphanN   = orphans.length;
    const removable = stale + orphanN;

    // Summary counts. These intentionally OVERLAP (e.g. a missing-PTR record is
    // also an active lease), so there is no meaningful grand total.
    const sActiveLease = records.filter(r => r.leased).length;
    const sConfigured  = records.filter(r => (r.reserved || r.override) && !r.leased).length;
    // Missing PTR among the backed rows above (lease / reservation / override) —
    // pure-stale records are reported only under "Possibly Stale / Orphaned".
    const sMissingPtr  = records.filter(r => !r.ptr_registered &&
                                            (r.reserved || r.leased || r.override)).length;
    const sStaleOrphan = stale + orphanN;
    const sUnknown     = records.filter(r => r.status === 'unknown').length;

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
        ['Static Reservations & Config Overrides', 'kea-blue', sConfigured,
         'Configured but not currently leased: a Kea reservation with no active lease yet, or an Unbound host override. Resolves whether or not a client is online.'],
        ['Missing Pointers', 'kea-amber', sMissingPtr,
         'Has a forward (A/AAAA) record but no matching reverse (PTR) record. Counts across the rows above.'],
        ['Possibly Stale / Orphaned', 'text-danger', sStaleOrphan,
         'A live override record in Unbound not backed by any active lease, Kea reservation, or configured host override — or a reverse (PTR) with no forward record. May be removable.' +
         '<br><br>These are not necessarily wrong: they are simply not backed by a Kea lease, reservation, or Unbound host override (for example, left over from an expired lease, or a record added by another tool). Cleaning removes them; anything still in use re-registers on the next lease renewal or sync.'],
    ];
    if (sUnknown > 0) {
        summaryRows.push(['Undetermined', 'text-muted', sUnknown,
            'Kea data is unavailable, so backing cannot be determined right now.']);
    }
    html += '<div class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading">' +
            '<h4 class="panel-title" style="display:inline;">DNS Record Summary</h4>' +
            '<a href="#" id="toggleDesc" class="small" style="float:right;"></a>' +
            '</div>' +
            '<div class="panel-body" style="padding:0;">' +
            '<table class="table table-condensed kea-summary" style="margin-bottom:0;">' +
            '<thead><tr><th>Category</th><th class="text-right">Count</th><th class="kea-desc">What it means</th></tr></thead><tbody>';
    summaryRows.forEach(function(r) {
        html += '<tr>' +
            '<td><span class="' + r[1] + '"><strong>' + r[0] + '</strong></span></td>' +
            '<td class="text-right ' + r[1] + '"><strong>' + r[2] + '</strong></td>' +
            '<td class="text-muted kea-desc">' + r[3] + '</td>' +
            '</tr>';
    });
    html += '</tbody></table></div></div>';

    // ── Stale / cleanup section ───────────────────────────────────────────────
    html += '<div class="panel panel-default" style="margin-bottom:16px;">' +
            '<div class="panel-heading"><h4 class="panel-title">Stale Record Cleanup</h4></div>' +
            '<div class="panel-body">';

    if (!audit.complete) {
        html += '<p class="text-muted">Cleanup unavailable — Kea data is required to safely identify stale records.</p>';
        updateCleanButton(false, 0);
    } else if (removable === 0) {
        html += '<p class="text-success"><i class="fa fa-check-circle"></i> No stale or orphaned records found. DNS is clean.</p>';
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
    if (records.length > 0) {
        html += '<div class="panel panel-default">' +
                '<div class="panel-heading"><h4 class="panel-title">DNS Records (' + records.length + ')</h4></div>' +
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
                '<th class="sortable kea-flag">Live Record</th>' +
                '<th class="sortable kea-flag">Static Reservation</th>' +
                '<th class="sortable kea-flag">Config Override</th>' +
                '</tr></thead><tbody>';

        records.forEach(function(r) {
            html += '<tr>' +
                '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                '<td class="kea-ip">'       + escapeHtml(r.ip)       + '</td>' +
                '<td>' + escapeHtml(r.type) + '</td>' +
                '<td>' + escapeHtml(r.ttl != null ? String(r.ttl) : '—') + '</td>' +
                '<td class="kea-flag" data-sort="' + ptrSortKey(r.ptr_state) + '">' + ptrIcon(r.ptr_state) + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.leased   ? '1' : '0') + '">' + flag(r.leased,   '#3c763d') + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.live     ? '1' : '0') + '">' + flag(r.live,     '#3c763d') + '</td>' +
                '<td class="kea-flag" data-sort="' + (r.reserved ? '1' : '0') + '">' + flag(r.reserved, '#2c6fbb') + '</td>' +
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
                '<i class="fa-solid fa-circle" style="color:#2c6fbb;"></i> yes&nbsp;' +
                '<i class="fa-regular fa-circle" style="color:#2c6fbb;"></i> no&nbsp;&mdash; blue = static reservation / config override' +
                '</span></div></div>';
    } else {
        html += '<div class="alert alert-info">No DNS records found.</div>';
    }

    // ── Reverse (PTR) records table ────────────────────────────────────────────
    const ptrs = audit.ptr_records || [];
    if (ptrs.length > 0) {
        html += '<div class="panel panel-default">' +
                '<div class="panel-heading"><h4 class="panel-title">Reverse (PTR) Records (' + ptrs.length + ')</h4></div>' +
                '<div class="panel-body" style="padding:0;">' +
                '<div class="table-responsive">' +
                '<table class="table table-striped table-condensed" style="margin:0;">' +
                '<thead><tr>' +
                '<th class="sortable">IP Address</th>' +
                '<th class="sortable">Reverse Name</th>' +
                '<th class="sortable">Points To</th>' +
                '<th class="sortable">TTL</th>' +
                '</tr></thead><tbody>';
        ptrs.forEach(function(p) {
            const tgts = p.targets || [];
            const pts = tgts.map(function(t) {
                return '<div>' + fwdIcon(t.fwd_state) + ' ' + escapeHtml(t.target) + '</div>';
            }).join('');
            const ttls = tgts.map(function(t) {
                return '<div>' + escapeHtml(t.ttl != null ? String(t.ttl) : '—') + '</div>';
            }).join('');
            const worstFwd = tgts.reduce(function(w, t) {
                const k = fwdSortKey(t.fwd_state); return k > w ? k : w;
            }, '0');
            html += '<tr>' +
                '<td class="kea-ip">' + escapeHtml(p.ip ? p.ip : '—') + '</td>' +
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
}

function updateCleanButton(complete, removable) {
    const btn  = $("#cleanBtn");
    const info = $("#cleanInfo");
    if (!complete) {
        btn.prop("disabled", true).html('<i class="fa fa-trash-o"></i> Clean Stale Records');
        if (info.length) info.text("Unavailable — Kea data required.");
    } else if (removable === 0) {
        btn.prop("disabled", true).html('<i class="fa fa-trash-o"></i> Clean Stale Records');
        if (info.length) info.text("");
    } else {
        btn.prop("disabled", false).html('<i class="fa fa-trash-o"></i> Clean ' + removable + ' Record' + (removable !== 1 ? 's' : '') + ' Now');
        if (info.length) info.text("");
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

<div class="content-box" style="padding:10px 15px;">
    <p class="text-muted small" style="margin:0 0 8px;">
        Compares Unbound's runtime DNS records against Kea leases, reservations, and
        Unbound Host Overrides. Records backed by an active source show as live; records
        with no backing can be removed with the Clean button. Use the Sync buttons to
        force a re-sync from Kea without restarting any service.
    </p>
    <div style="display:flex; align-items:center;">
        <label style="margin:0; font-weight:normal; color:#777; cursor:pointer;">
            <input type="checkbox" id="autoRefreshCheck" checked style="margin-right:5px;">
            Auto-refresh every 30 seconds
        </label>
        <button id="refreshBtn" class="btn btn-primary btn-sm" style="margin-left:20px;">
            <i class="fa fa-refresh"></i> Refresh Now
        </button>
    </div>
    <div style="margin-top:8px;">
        <button id="cleanBtn" class="btn btn-warning btn-sm" disabled>
            <i class="fa fa-trash-o"></i> Clean Stale Records
        </button>
        <button id="syncStaticBtn" class="btn btn-default btn-sm" style="display:none; margin-left:8px;">
            <i class="fa fa-download"></i> Sync Static Records
        </button>
        <button id="syncDynamicBtn" class="btn btn-default btn-sm" style="display:none; margin-left:8px;">
            <i class="fa fa-download"></i> Sync Active DHCP Leases
        </button>
    </div>
</div>

<div id="statusLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading DNS registration status...</p>
</div>

<div id="statusError"  style="display:none; padding:10px;"></div>
<div id="statusContent" style="display:none; padding:10px;"></div>
</content>

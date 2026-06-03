{#
 # Copyright (c) 2026 tkr
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
    .kea-summary td, .kea-summary th { vertical-align: middle; }
    .kea-summary tfoot th { border-top: 2px solid #ddd; }
    /* Explicit blue — OPNsense's theme renders text-primary/label-primary orange. */
    .kea-blue            { color: #2c6fbb; }
    .label.label-kea-blue { background-color: #2c6fbb; }
</style>

<script>
$( document ).ready(function() {
    loadAuditData();
    setInterval(loadAuditData, 30000);

    $("#refreshBtn").click(function() { loadAuditData(); });

    $("#cleanBtn").click(function() {
        if (!confirm("Remove stale and orphaned DNS records from Unbound?\n\nThe stale set is recomputed server-side before removal.")) {
            return;
        }
        const btn = $(this);
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
            const va = $(a).children("td").eq(col).text().trim();
            const vb = $(b).children("td").eq(col).text().trim();
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

function statusBadge(status) {
    const map = {
        'ok':           '<span class="label label-success">Registered</span>',
        'missing-PTR':  '<span class="label label-warning">Missing PTR</span>',
        'stale':        '<span class="label label-danger">Possibly Stale</span>',
        'orphaned-PTR': '<span class="label label-danger">Possible Orphan PTR</span>',
        'static':       '<span class="label label-kea-blue">Static</span>',
        'unknown':      '<span class="label label-default">Unknown</span>'
    };
    return map[status] || '<span class="label label-default">' + escapeHtml(status) + '</span>';
}

function renderAuditData(audit) {
    const records = audit.records || [];
    const orphans  = audit.orphaned_ptrs || [];

    const ok      = records.filter(r => r.status === 'ok').length;
    const missing = records.filter(r => r.status === 'missing-PTR').length;
    const stale   = records.filter(r => r.status === 'stale').length;
    const staticN = records.filter(r => r.status === 'static').length;
    const unknown = records.filter(r => r.status === 'unknown').length;
    const orphanN = orphans.length;
    const removable = stale + orphanN;
    const total     = records.length + orphanN;

    let html = '';

    // Kea unavailable warning
    if (!audit.complete && audit.kea_error) {
        html += '<div class="alert alert-warning alert-dismissible" role="alert">' +
                '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
                '<strong>Warning:</strong> DNS data is incomplete — Kea Control Agent unavailable: ' +
                escapeHtml(audit.kea_error) + '</div>';
    }

    // ── Summary table ─────────────────────────────────────────────────────────
    const summaryRows = [
        ['Dynamically Registered', 'text-success', ok,
         'Forward record (A/AAAA) registered into Unbound by this plugin from a current Kea active lease or static reservation, with a matching reverse (PTR) record. Nothing to do.'],
        ['Static', 'kea-blue', staticN,
         'An Unbound host override, or a static DHCP mapping OPNsense keeps in host_entries.conf. Managed by Unbound — this plugin never changes it. (Kea static reservations appear above as Dynamically Registered.)'],
        ['Missing PTR', 'text-warning', missing,
         'The forward record is registered, but it has no matching reverse (PTR) record.'],
        ['Possibly Stale', 'text-danger', stale,
         'Still in Unbound but not backed by any Kea lease, Kea reservation, or Unbound host override — so it may be removable (see note below).'],
        ['Possible Orphan PTR', 'text-danger', orphanN,
         'A reverse (PTR) record with no matching forward record, and not from Kea or an Unbound host override — possibly removable (see note below).'],
    ];
    if (unknown > 0) {
        summaryRows.push(['Unknown', 'text-muted', unknown,
            'Kea data is unavailable, so staleness cannot be determined right now.']);
    }
    html += '<div class="panel panel-default" style="margin-bottom:8px;">' +
            '<div class="panel-heading"><h4 class="panel-title">DNS Record Summary</h4></div>' +
            '<div class="panel-body" style="padding:0;">' +
            '<table class="table table-condensed kea-summary" style="margin-bottom:0;">' +
            '<thead><tr><th>Category</th><th class="text-right">Count</th><th>What it means</th></tr></thead><tbody>';
    summaryRows.forEach(function(r) {
        html += '<tr>' +
            '<td><span class="' + r[1] + '"><strong>' + r[0] + '</strong></span></td>' +
            '<td class="text-right ' + r[1] + '"><strong>' + r[2] + '</strong></td>' +
            '<td class="text-muted">' + r[3] + '</td>' +
            '</tr>';
    });
    html += '</tbody>' +
            '<tfoot><tr><th>Total</th><th class="text-right">' + total + '</th><th></th></tr></tfoot>' +
            '</table></div></div>';
    html += '<p class="text-muted small" style="margin:0 0 16px;">' +
            '<i class="fa fa-info-circle"></i> <strong>Stale</strong> and <strong>orphaned</strong> entries are not necessarily wrong — ' +
            'they are simply not backed by a Kea lease, a Kea reservation, or an Unbound host override (for example, left over from ' +
            'an expired lease, or added by another tool). Cleaning removes them; anything still in use re-registers on the next lease renewal or sync.' +
            '</p>';

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
                '<table class="table table-striped table-condensed" style="margin:0;">' +
                '<thead><tr>' +
                '<th class="sortable">Hostname</th>' +
                '<th class="sortable">IP Address</th>' +
                '<th class="sortable">Type</th>' +
                '<th class="sortable">TTL</th>' +
                '<th class="sortable">Source</th>' +
                '<th class="sortable">Registration</th>' +
                '<th class="sortable">In Unbound</th>' +
                '<th class="sortable">PTR</th>' +
                '</tr></thead><tbody>';

        records.forEach(function(r) {
            const inUnbound = r.in_unbound
                ? '<span class="label label-success">Yes</span>'
                : '<span class="label label-danger">No</span>';
            const ptr = r.ptr_registered
                ? '<span class="label label-success">&#10003;</span>'
                : '<span class="label label-default">&#10007;</span>';

            html += '<tr>' +
                '<td class="kea-hostname">' + escapeHtml(r.hostname) + '</td>' +
                '<td class="kea-ip">'       + escapeHtml(r.ip)       + '</td>' +
                '<td>' + escapeHtml(r.type)   + '</td>' +
                '<td>' + escapeHtml(r.ttl != null ? String(r.ttl) : '—') + '</td>' +
                '<td>' + escapeHtml(r.source) + '</td>' +
                '<td>' + statusBadge(r.status) + '</td>' +
                '<td>' + inUnbound + '</td>' +
                '<td>' + ptr + '</td>' +
                '</tr>';
        });

        html += '</tbody></table></div></div></div>';
    } else {
        html += '<div class="alert alert-info">No DNS records found.</div>';
    }

    $("#statusContent").html(html);
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

<div class="content-box" style="padding:10px 15px;">
    <div>
        <button id="refreshBtn" class="btn btn-primary btn-sm">
            <i class="fa fa-refresh"></i> Refresh Now
        </button>
        <small class="text-muted" style="margin-left:12px;">Auto-refresh every 30 seconds</small>
    </div>
    <div style="margin-top:8px;">
        <button id="syncStaticBtn" class="btn btn-default btn-sm">
            <i class="fa fa-download"></i> Sync Static DHCP Reservations
        </button>
        <button id="syncDynamicBtn" class="btn btn-default btn-sm" style="margin-left:8px;">
            <i class="fa fa-download"></i> Sync Active DHCP Leases
        </button>
        <button id="cleanBtn" class="btn btn-warning btn-sm" disabled style="margin-left:8px;">
            <i class="fa fa-trash-o"></i> Clean Stale Records
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

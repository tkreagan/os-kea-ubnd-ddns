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
    .stat-card    { text-align: center; padding: 12px 8px; }
    .stat-card h4 { margin: 0 0 4px; font-size: 1.6em; }
    .stat-card small { font-size: 0.8em; }
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
        'ok':           '<span class="label label-success">OK</span>',
        'missing-PTR':  '<span class="label label-warning">Missing PTR</span>',
        'stale':        '<span class="label label-info">Stale</span>',
        'orphaned-PTR': '<span class="label label-danger">Orphaned</span>',
        'static':       '<span class="label label-default">Static</span>',
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
    const orphanN = orphans.length;
    const removable = stale + orphanN;

    let html = '';

    // Kea unavailable warning
    if (!audit.complete && audit.kea_error) {
        html += '<div class="alert alert-warning alert-dismissible" role="alert">' +
                '<button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>' +
                '<strong>Warning:</strong> DNS data is incomplete — Kea Control Agent unavailable: ' +
                escapeHtml(audit.kea_error) + '</div>';
    }

    // ── Summary stats ────────────────────────────────────────────────────────
    html += '<div class="row" style="margin-bottom:16px;">';
    html += statCard(ok,      'OK',           'text-success');
    html += statCard(missing, 'Missing PTR',  'text-warning');
    html += statCard(stale,   'Stale',        'text-info');
    html += statCard(orphanN, 'Orphaned PTR', 'text-danger');
    html += statCard(staticN, 'Static',       'text-muted');
    html += '</div>';

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
                stale + ' stale hostname' + (stale !== 1 ? 's' : '') +
                (orphanN > 0 ? ', ' + orphanN + ' orphaned PTR' + (orphanN !== 1 ? 's' : '') : '') + '.</p>';
        updateCleanButton(true, removable);

        // List the stale names if present
        if (stale > 0) {
            const staleNames = records.filter(r => r.status === 'stale').map(r => r.hostname);
            const unique = [...new Set(staleNames)].sort();
            html += '<p class="text-muted" style="margin-bottom:4px;"><strong>Stale hostnames:</strong></p><ul style="margin-bottom:8px;">';
            unique.forEach(n => { html += '<li class="kea-hostname">' + escapeHtml(n) + '</li>'; });
            html += '</ul>';
        }
        if (orphanN > 0) {
            html += '<p class="text-muted" style="margin-bottom:4px;"><strong>Orphaned PTR records:</strong></p><ul>';
            orphans.forEach(o => { html += '<li class="kea-hostname">' + escapeHtml(o.ptr_name) + '</li>'; });
            html += '</ul>';
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

function statCard(count, label, colorClass) {
    return '<div class="col-xs-2 col-sm-2">' +
           '<div class="panel panel-default stat-card">' +
           '<h4 class="' + colorClass + '">' + count + '</h4>' +
           '<small class="text-muted">' + label + '</small>' +
           '</div></div>';
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

<div class="content-box" style="padding:10px 15px 5px;">
    <button id="refreshBtn" class="btn btn-primary btn-sm">
        <i class="fa fa-refresh"></i> Refresh Now
    </button>
    <button id="cleanBtn"   class="btn btn-warning btn-sm" disabled style="margin-left:8px;">
        <i class="fa fa-trash-o"></i> Clean Stale Records
    </button>
    <small class="text-muted" style="margin-left:12px;">Auto-refresh every 30 seconds</small>
</div>

<div id="statusLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading DNS registration status...</p>
</div>

<div id="statusError"  style="display:none; padding:10px;"></div>
<div id="statusContent" style="display:none; padding:10px;"></div>
</content>

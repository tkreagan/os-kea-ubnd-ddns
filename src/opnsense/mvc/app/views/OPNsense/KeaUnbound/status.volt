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

<script>
$( document ).ready(function() {
    loadAuditData();

    // Refresh every 30 seconds
    setInterval(loadAuditData, 30000);

    $("#refreshBtn").click(function() {
        loadAuditData();
    });

    $("#cleanBtn").click(function() {
        if (!confirm("Remove stale and orphaned DNS records from Unbound? " +
                     "The current stale set is recomputed server-side and removed.")) {
            return;
        }
        const btn = $(this);
        btn.prop("disabled", true);
        $("#cleanInfo").text("Cleaning…");
        ajaxCall("/api/keaunbound/general/clean", {}, function() {
            // Re-audit so the removed rows disappear from the view.
            loadAuditData();
        });
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
        timeout: 10000,
        success: function(data) {
            if (data.status === 'error') {
                showError(data.message || 'Audit failed');
                return;
            }

            if (!data.audit) {
                showError('Invalid response from audit endpoint');
                return;
            }

            renderAuditData(data.audit);
            $("#statusLoader").hide();
            $("#statusContent").show();
        },
        error: function(xhr, status, error) {
            let message = 'Failed to load audit data';
            if (status === 'timeout') {
                message = 'Request timeout - audit is taking too long';
            } else if (xhr.status === 0) {
                message = 'Connection error';
            }
            showError(message);
        }
    });
}

function showError(message) {
    $("#statusLoader").hide();
    $("#cleanBtn").prop("disabled", true);
    $("#cleanInfo").text("");
    $("#statusError").html(`<div class="alert alert-danger alert-dismissible fade show" role="alert">
        <strong>Error:</strong> ${escapeHtml(message)}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>`);
    $("#statusError").show();
}

function escapeHtml(text) {
    let map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function updateCleanButton(complete, removable) {
    const btn = $("#cleanBtn");
    const info = $("#cleanInfo");
    if (!complete) {
        btn.prop("disabled", true);
        info.text("Cleanup unavailable while the Kea Control Agent is unreachable.");
    } else if (removable === 0) {
        btn.prop("disabled", true);
        info.text("No stale or orphaned records to clean.");
    } else {
        btn.prop("disabled", false);
        info.text(removable + " stale/orphaned record(s) can be cleaned.");
    }
}

function renderAuditData(audit) {
    let html = '';

    // Gate the Clean button on Kea availability + a nonzero removable set.
    const recs = audit.records || [];
    const staleCount = recs.filter(r => r.status === 'stale').length;
    const orphanCount = (audit.orphaned_ptrs || []).length;
    updateCleanButton(audit.complete, staleCount + orphanCount);

    // Show warning if Kea was unavailable
    if (!audit.complete && audit.kea_error) {
        html += `<div class="alert alert-warning alert-dismissible fade show" role="alert">
            <strong>Warning:</strong> DNS registration status is incomplete. Kea Control Agent was unavailable: ${escapeHtml(audit.kea_error)}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
    }

    // Show summary statistics
    if (audit.records && audit.records.length > 0) {
        let ok = audit.records.filter(r => r.status === 'ok').length;
        let missing = audit.records.filter(r => r.status === 'missing-PTR').length;
        let stale = audit.records.filter(r => r.status === 'stale').length;
        let orphaned = (audit.orphaned_ptrs ? audit.orphaned_ptrs.length : 0);
        let staticRecords = audit.records.filter(r => r.status === 'static').length;

        html += `<div class="row">
            <div class="col-md-2">
                <div class="card">
                    <div class="card-body text-center">
                        <h4 class="text-success">${ok}</h4>
                        <small class="text-muted">OK</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card">
                    <div class="card-body text-center">
                        <h4 class="text-warning">${missing}</h4>
                        <small class="text-muted">Missing PTR</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card">
                    <div class="card-body text-center">
                        <h4 class="text-info">${stale}</h4>
                        <small class="text-muted">Stale</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card">
                    <div class="card-body text-center">
                        <h4 class="text-danger">${orphaned}</h4>
                        <small class="text-muted">Orphaned PTR</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card">
                    <div class="card-body text-center">
                        <h4 class="text-secondary">${staticRecords}</h4>
                        <small class="text-muted">Static</small>
                    </div>
                </div>
            </div>
        </div><br/>`;
    }

    // DNS Records Table
    if (audit.records && audit.records.length > 0) {
        html += `<div class="card">
            <div class="card-header">
                <h4>DNS Records (${audit.records.length})</h4>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm table-striped">
                        <thead>
                            <tr>
                                <th>Hostname</th>
                                <th>IP Address</th>
                                <th>Type</th>
                                <th>Source</th>
                                <th>Status</th>
                                <th>In Unbound</th>
                                <th>PTR</th>
                            </tr>
                        </thead>
                        <tbody>`;

        audit.records.forEach(record => {
            let statusBadge = getStatusBadge(record.status);
            let inUnbound = record.in_unbound ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-danger">No</span>';
            let ptr = record.ptr_registered ? '<span class="badge bg-success">✓</span>' : '<span class="badge bg-secondary">✗</span>';

            html += `<tr>
                <td><code>${escapeHtml(record.hostname)}</code></td>
                <td><code>${escapeHtml(record.ip)}</code></td>
                <td><span class="badge bg-info">${escapeHtml(record.type)}</span></td>
                <td><span class="badge bg-secondary">${escapeHtml(record.source)}</span></td>
                <td>${statusBadge}</td>
                <td>${inUnbound}</td>
                <td>${ptr}</td>
            </tr>`;
        });

        html += `</tbody>
                    </table>
                </div>
            </div>
        </div><br/>`;
    } else {
        html += '<div class="alert alert-info">No DNS records found.</div>';
    }

    // Orphaned PTRs
    if (audit.orphaned_ptrs && audit.orphaned_ptrs.length > 0) {
        html += `<div class="card">
            <div class="card-header">
                <h4>Orphaned PTR Records (${audit.orphaned_ptrs.length})</h4>
            </div>
            <div class="card-body">
                <p class="text-muted">These PTR records are registered in Unbound but don't correspond to any known Kea reservation, lease, or OPNsense-managed entry. They should be cleaned up.</p>
                <div class="table-responsive">
                    <table class="table table-sm table-striped">
                        <thead>
                            <tr>
                                <th>PTR Name</th>
                                <th>Data</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>`;

        audit.orphaned_ptrs.forEach(ptr => {
            html += `<tr>
                <td><code>${escapeHtml(ptr.ptr_name)}</code></td>
                <td><code>${escapeHtml(ptr.data)}</code></td>
                <td><span class="badge bg-danger">Orphaned</span></td>
            </tr>`;
        });

        html += `</tbody>
                    </table>
                </div>
            </div>
        </div><br/>`;
    }

    $("#statusContent").html(html);
}

function getStatusBadge(status) {
    switch(status) {
        case 'ok':
            return '<span class="badge bg-success">OK</span>';
        case 'missing-PTR':
            return '<span class="badge bg-warning">Missing PTR</span>';
        case 'stale':
            return '<span class="badge bg-info">Stale</span>';
        case 'orphaned-PTR':
            return '<span class="badge bg-danger">Orphaned PTR</span>';
        case 'static':
            return '<span class="badge bg-secondary">Static</span>';
        default:
            return '<span class="badge bg-secondary">' + escapeHtml(status) + '</span>';
    }
}
</script>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <button id="refreshBtn" class="btn btn-primary">
                <i class="fa fa-refresh"></i> Refresh Now
            </button>
            <button id="cleanBtn" class="btn btn-warning" disabled>
                <i class="fa fa-trash"></i> Clean Stale Records Now
            </button>
            <small class="text-muted" style="margin-left: 10px;">
                Auto-refresh every 30 seconds
            </small>
            <div><small id="cleanInfo" class="text-muted"></small></div>
        </div>
    </div>
    <br/>

    <div id="statusLoader" style="display: none; text-align: center;">
        <div class="spinner-border" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
        <p>Loading DNS registration status...</p>
    </div>

    <div id="statusError" style="display: none;"></div>

    <div id="statusContent" style="display: none;"></div>
</div>

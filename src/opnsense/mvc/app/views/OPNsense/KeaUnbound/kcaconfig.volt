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
    loadKeaConfig();

    // Refresh every 30 seconds
    setInterval(loadKeaConfig, 30000);

    $("#refreshBtn").click(function() {
        loadKeaConfig();
    });
});

function loadKeaConfig() {
    $("#configLoader").show();
    $("#configContent").hide();
    $("#configError").hide();

    $.ajax({
        url: '/api/keaunbound/kca-config/check',
        type: 'GET',
        dataType: 'json',
        timeout: 10000,
        success: function(data) {
            if (data.status === 'error' && data.kea_error) {
                showError(data.kea_error);
                return;
            }

            renderKeaConfig(data);
            $("#configLoader").hide();
            $("#configContent").show();
        },
        error: function(xhr, status, error) {
            let message = 'Failed to load Kea configuration';
            if (status === 'timeout') {
                message = 'Request timeout - check that Kea Control Agent is running';
            } else if (xhr.status === 0) {
                message = 'Connection error - Kea Control Agent may not be running';
            }
            showError(message);
        }
    });
}

function showError(message) {
    $("#configLoader").hide();
    $("#configError").html(`<div class="alert alert-danger alert-dismissible fade show" role="alert">
        <strong>Error:</strong> ${escapeHtml(message)}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>`);
    $("#configError").show();
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

function renderKeaConfig(data) {
    let html = '';

    // Info banner
    html += `<div class="alert alert-info alert-dismissible fade show" role="alert">
        <strong>DDNS Configuration Check:</strong> This shows which subnets in Kea are configured to send DHCP-DDNS updates. Only subnets with DDNS enabled will have their leases registered to DNS automatically.
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>`;

    // IPv4 Subnets
    if (data.ipv4_subnets && data.ipv4_subnets.length > 0) {
        html += renderSubnetTable('IPv4 Subnets', data.ipv4_subnets);
    } else if (data.ipv4_subnets) {
        html += `<div class="card">
            <div class="card-header"><h4>IPv4 Subnets</h4></div>
            <div class="card-body">
                <p class="text-muted">No IPv4 subnets configured in Kea DHCP.</p>
            </div>
        </div><br/>`;
    }

    // IPv6 Subnets
    if (data.ipv6_subnets && data.ipv6_subnets.length > 0) {
        html += renderSubnetTable('IPv6 Subnets', data.ipv6_subnets);
    } else if (data.ipv6_subnets) {
        html += `<div class="card">
            <div class="card-header"><h4>IPv6 Subnets</h4></div>
            <div class="card-body">
                <p class="text-muted">No IPv6 subnets configured in Kea DHCP.</p>
            </div>
        </div><br/>`;
    }

    // Summary
    let configured = (data.ipv4_subnets || []).concat(data.ipv6_subnets || []).filter(s => s.status === 'configured').length;
    let notConfigured = (data.ipv4_subnets || []).concat(data.ipv6_subnets || []).filter(s => s.status === 'not-configured').length;
    let total = (data.ipv4_subnets || []).length + (data.ipv6_subnets || []).length;

    html += `<div class="row">
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h4 class="text-success">${configured}</h4>
                    <small class="text-muted">Configured for DDNS</small>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h4 class="text-warning">${notConfigured}</h4>
                    <small class="text-muted">Not Configured</small>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h4 class="text-info">${total}</h4>
                    <small class="text-muted">Total Subnets</small>
                </div>
            </div>
        </div>
    </div><br/>`;

    // Configuration guidance
    if (notConfigured > 0) {
        html += `<div class="alert alert-warning">
            <strong>Action Needed:</strong> Some subnets are not configured for DDNS. To enable DDNS for a subnet, edit the Kea DHCP configuration and add <code>"ddns-send-updates": true</code> to the subnet definition. See the Settings tab for documentation.
        </div>`;
    } else if (total > 0 && configured === total) {
        html += `<div class="alert alert-success">
            <strong>All subnets configured:</strong> All configured subnets are set to send DDNS updates. Leases will be registered to DNS automatically.
        </div>`;
    }

    $("#configContent").html(html);
}

function renderSubnetTable(title, subnets) {
    let html = `<div class="card">
        <div class="card-header">
            <h4>${escapeHtml(title)} (${subnets.length})</h4>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm table-striped">
                    <thead>
                        <tr>
                            <th>Subnet</th>
                            <th>DDNS Enabled</th>
                            <th>Status</th>
                            <th>Comment</th>
                        </tr>
                    </thead>
                    <tbody>`;

    subnets.forEach(subnet => {
        let ddnsIcon = subnet.ddns_enabled ? '✅ Yes' : '❌ No';
        let ddnsBadge = subnet.ddns_enabled ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-danger">No</span>';
        let statusBadge = subnet.status === 'configured'
            ? '<span class="badge bg-success">Configured</span>'
            : '<span class="badge bg-warning">Not Configured</span>';
        let comment = subnet.comment ? escapeHtml(subnet.comment) : '<span class="text-muted">-</span>';

        html += `<tr>
            <td><code>${escapeHtml(subnet.subnet)}</code></td>
            <td>${ddnsBadge}</td>
            <td>${statusBadge}</td>
            <td>${comment}</td>
        </tr>`;
    });

    html += `</tbody>
                </table>
            </div>
        </div>
    </div><br/>`;

    return html;
}
</script>

<div class="content-box">
    <div class="row">
        <div class="col-md-12">
            <button id="refreshBtn" class="btn btn-primary">
                <i class="fa fa-refresh"></i> Refresh Now
            </button>
            <small class="text-muted" style="margin-left: 10px;">
                Auto-refresh every 30 seconds
            </small>
        </div>
    </div>
    <br/>

    <div id="configLoader" style="display: none; text-align: center;">
        <div class="spinner-border" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
        <p>Loading Kea DHCP configuration...</p>
    </div>

    <div id="configError" style="display: none;"></div>

    <div id="configContent" style="display: none;"></div>
</div>

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
    .kea-subnet  { font-family: monospace; font-size: 0.9em; }
    .stat-card   { text-align: center; padding: 12px 8px; }
    .stat-card h4 { margin: 0 0 4px; font-size: 1.6em; }
    .stat-card small { font-size: 0.8em; }
</style>

<script>
$( document ).ready(function() {
    loadKeaConfig();
    setInterval(loadKeaConfig, 30000);
    $("#refreshBtn").click(function() { loadKeaConfig(); });
});

function loadKeaConfig() {
    $("#configLoader").show();
    $("#configContent").hide();
    $("#configError").hide();

    $.ajax({
        url: '/api/keaunbound/kcaconfig/check',
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
        error: function(xhr, status) {
            showError(status === 'timeout'
                ? 'Request timed out — check that Kea Control Agent is running'
                : 'Failed to load Kea configuration');
        }
    });
}

function showError(message) {
    $("#configLoader").hide();
    $("#configError").html(
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

const BUCKET_LABELS = {
    'ok':            { label: 'OK',              cls: 'label-success' },
    'tsig_mismatch': { label: 'TSIG Mismatch',   cls: 'label-danger'  },
    'wrong_target':  { label: 'Other Target',    cls: 'label-warning' },
    'no_ddns':       { label: 'No DDNS',         cls: 'label-default' },
    'd2_offline':    { label: 'DDNS Agent Down', cls: 'label-danger'  },
};

function bucketBadge(status) {
    const b = BUCKET_LABELS[status] || { label: status, cls: 'label-default' };
    return '<span class="label ' + b.cls + '">' + b.label + '</span>';
}

function renderKeaConfig(data) {
    const v4  = data.ipv4_subnets || [];
    const v6  = data.ipv6_subnets || [];
    const all = v4.concat(v6);

    const ok       = all.filter(s => s.ddns_status === 'ok').length;
    const tsig     = all.filter(s => s.ddns_status === 'tsig_mismatch').length;
    const wrong    = all.filter(s => s.ddns_status === 'wrong_target').length;
    const no_ddns  = all.filter(s => s.ddns_status === 'no_ddns').length;
    const d2_off   = all.filter(s => s.ddns_status === 'd2_offline').length;
    const total    = all.length;
    const problems = total - ok;

    let html = '';

    // ── Listener info ─────────────────────────────────────────────────────────
    if (data.our_listener) {
        const l = data.our_listener;
        const tsigInfo = l.tsig_enabled ? ' + TSIG' : ' (no TSIG)';
        const d2Info = data.d2_reachable
            ? '<span class="label label-success">Configured</span>'
            : '<span class="label label-warning">Config not found</span>';
        html += '<div class="alert alert-info" style="margin-bottom:12px;">' +
                '<i class="fa fa-info-circle"></i> Plugin listener: ' +
                '<strong>' + escapeHtml(l.address) + ':' + l.port + '</strong>' + escapeHtml(tsigInfo) +
                ' &nbsp;|&nbsp; DHCP-DDNS daemon: ' + d2Info + '</div>';
    }

    // ── Summary stats ─────────────────────────────────────────────────────────
    html += '<div class="row" style="margin-bottom:16px;">';
    html += statCard(ok,      'Correctly Configured', 'text-success');
    html += statCard(wrong,   'Other Target',         'text-warning');
    html += statCard(tsig + d2_off, 'Needs Attention','text-danger');
    html += statCard(no_ddns, 'No DDNS',              'text-muted');
    html += '</div>';

    // ── Status alert ──────────────────────────────────────────────────────────
    if (total === 0) {
        html += '<div class="alert alert-info">No subnets found in Kea DHCP.</div>';
    } else if (ok === total) {
        html += '<div class="alert alert-success"><i class="fa fa-check-circle"></i> ' +
                '<strong>All ' + total + ' subnet' + (total !== 1 ? 's are' : ' is') +
                ' correctly configured</strong> to send DDNS updates to this plugin.</div>';
    } else {
        let msgs = [];
        if (d2_off  > 0) msgs.push(d2_off  + ' need the DDNS Agent running');
        if (wrong   > 0) msgs.push(wrong   + ' sending to a different DNS server/port');
        if (tsig    > 0) msgs.push(tsig    + ' with a TSIG configuration mismatch');
        if (no_ddns > 0) msgs.push(no_ddns + ' with DDNS disabled');
        html += '<div class="alert alert-warning"><strong>Action Needed:</strong> ' +
                problems + ' subnet' + (problems !== 1 ? 's have' : ' has') + ' issues: ' +
                msgs.join('; ') + '. See the detail column below.</div>';
    }

    // ── Subnet tables ─────────────────────────────────────────────────────────
    html += subnetPanel('IPv4 Subnets', v4);
    html += subnetPanel('IPv6 Subnets', v6);

    // ── Contextual fix instructions ───────────────────────────────────────────
    if (problems > 0) {
        html += fixGuide(wrong > 0, tsig > 0, no_ddns > 0, d2_off > 0, data.our_listener);
    }

    $("#configContent").html(html);
}

function fixGuide(hasWrong, hasTsig, hasNoDdns, hasD2Off, listener) {
    const port = listener ? listener.port : 53535;
    let html = '<div class="panel panel-default" style="margin-top:8px;">' +
               '<div class="panel-heading" style="cursor:pointer;" onclick="$(\'#fixGuideBody\').toggle();">' +
               '<h4 class="panel-title"><i class="fa fa-wrench"></i> How to fix &nbsp;' +
               '<small class="text-muted">(click to expand)</small></h4></div>' +
               '<div id="fixGuideBody" style="display:none;">' +
               '<div class="panel-body">';

    if (hasD2Off) {
        html += '<h5><span class="label label-danger">DDNS Agent Down</span> &nbsp;Start the Kea DHCP-DDNS daemon</h5>' +
                '<ol>' +
                '<li>Go to <strong>Services → Kea DHCP → DDNS Agent</strong></li>' +
                '<li>Check <strong>Enabled</strong></li>' +
                '<li>Leave Bind address as <code>127.0.0.1</code> and Bind port as <code>53001</code></li>' +
                '<li>Click <strong>Apply</strong></li>' +
                '</ol>' +
                '<p class="text-muted">The DDNS Agent must be running before any DHCP lease events can trigger DNS updates. ' +
                'Once enabled, return here — subnets with correct subnet-level settings will show OK.</p>';
    }

    html += '<p class="text-muted">Per-subnet settings are in <strong>Services → Kea DHCP → Kea DHCPv4 → Subnets</strong>. ' +
            'Edit the subnet, scroll to the <strong>Dynamic DNS</strong> section, and click <strong>Advanced</strong> ' +
            'to reveal the port and TSIG fields. Apply after saving.</p>';

    if (hasNoDdns) {
        html += '<h5><span class="label label-default">No DDNS</span> &nbsp;Enable DDNS for this subnet</h5>' +
                '<ol>' +
                '<li>Set <strong>DNS forward zone</strong> to your domain (e.g. <code>plhm.rgn.cm</code>)</li>' +
                '<li>Set <strong>DNS qualifying suffix</strong> to the same value</li>' +
                '<li>Optionally set <strong>DNS reverse zone</strong> (e.g. <code>1.10.10.in-addr.arpa.</code>)</li>' +
                '<li>Click <strong>Advanced</strong> and set the following:</li>' +
                '<li><strong>DNS server address:</strong> <code>127.0.0.1</code></li>' +
                '<li><strong>DNS server port:</strong> <code>' + port + '</code></li>' +
                '<li><strong>Override no update: ✓</strong> — without this, clients that send a "don\'t update DNS" flag ' +
                '(common on Windows) are honoured and no DNS entry is registered for them.</li>' +
                '<li><strong>Override client update: ✓</strong> — without this, clients that claim they will handle ' +
                'their own forward DNS update may not get PTR records registered, causing Missing PTR entries in the Lease Audit.</li>' +
                '<li><strong>Update on renew: leave off</strong> — sending a DDNS update on every lease renewal adds ' +
                'unnecessary load with no benefit in normal operation; the scheduled cleanup handles any stale entries.</li>' +
                '<li><strong>Conflict resolution mode: <code>no-check-with-dhcid</code></strong> — the default ' +
                '<code>check-with-dhcid</code> mode uses DHCID records to prevent different clients from overwriting ' +
                'each other\'s DNS entries, but it also blocks dual-stack clients (same device, different DHCPv4/DHCPv6 ' +
                'identifiers) from registering both A and AAAA records. Since this plugin writes to Unbound (a resolver, ' +
                'not an authoritative server) and is the sole writer, DHCID protection provides no benefit and only causes ' +
                'problems. Use <code>no-check-with-dhcid</code> to allow dual-stack and avoid Missing PTR issues. ' +
                '(See OPNsense issue #10212.)</li>' +
                '<li>Save and Apply</li>' +
                '</ol>';
    }

    if (hasWrong) {
        html += '<h5><span class="label label-warning">Other Target</span> &nbsp;Point this subnet at this plugin</h5>' +
                '<ol>' +
                '<li>Click <strong>Advanced</strong> in the Dynamic DNS section</li>' +
                '<li>Set <strong>DNS server address</strong> to <code>127.0.0.1</code></li>' +
                '<li>Set <strong>DNS server port</strong> to <code>' + port + '</code></li>' +
                '<li>Save and Apply</li>' +
                '</ol>' +
                '<p class="text-muted">Note: if this subnet intentionally sends DDNS updates elsewhere, ' +
                'no change is needed — the amber status is informational only.</p>';
    }

    if (hasTsig) {
        html += '<h5><span class="label label-danger">TSIG Mismatch</span> &nbsp;Fix TSIG authentication</h5>' +
                '<p>Both sides must agree on TSIG — either both enabled with matching key, or both disabled.</p>' +
                '<strong>To enable TSIG on this subnet:</strong>' +
                '<ol>' +
                '<li>Click <strong>Advanced</strong> in the Dynamic DNS section</li>' +
                '<li>Set <strong>TSIG key name</strong> to match the plugin\'s key name (Settings tab)</li>' +
                '<li>Set <strong>TSIG secret</strong> to the same base64-encoded secret</li>' +
                '<li>Set <strong>TSIG algorithm</strong> to match (e.g. HMAC-SHA256)</li>' +
                '<li>Save and Apply</li>' +
                '</ol>' +
                '<strong>To disable TSIG instead:</strong> go to the Kea Unbound Settings tab and uncheck ' +
                '<em>Enable TSIG authentication</em>, then Apply.';
    }

    html += '</div></div></div>';
    return html;
}

function subnetPanel(title, subnets) {
    if (subnets.length === 0) {
        return '<div class="panel panel-default" style="margin-bottom:12px;">' +
               '<div class="panel-heading"><h4 class="panel-title">' + title + '</h4></div>' +
               '<div class="panel-body"><p class="text-muted" style="margin:0;">No ' +
               title.toLowerCase() + ' configured in Kea DHCP.</p></div></div>';
    }

    let rows = '';
    subnets.forEach(function(s) {
        const comment = s.comment
            ? escapeHtml(s.comment)
            : '<span class="text-muted">—</span>';
        const target = s.target
            ? '<span class="kea-subnet">' + escapeHtml(s.target) + '</span>'
            : '<span class="text-muted">—</span>';

        rows += '<tr>' +
                '<td class="kea-subnet">'  + escapeHtml(s.subnet)       + '</td>' +
                '<td>'                     + bucketBadge(s.ddns_status)  + '</td>' +
                '<td class="text-muted" style="font-size:0.9em;">' + escapeHtml(s.detail || '') + '</td>' +
                '<td>'                     + target                      + '</td>' +
                '<td>'                     + comment                     + '</td>' +
                '</tr>';
    });

    return '<div class="panel panel-default" style="margin-bottom:12px;">' +
           '<div class="panel-heading"><h4 class="panel-title">' + title +
           ' (' + subnets.length + ')</h4></div>' +
           '<div class="panel-body" style="padding:0;">' +
           '<div class="table-responsive">' +
           '<table class="table table-striped table-condensed" style="margin:0;">' +
           '<thead><tr><th>Subnet</th><th>Status</th><th>Detail</th><th>DNS Target</th><th>Comment</th></tr></thead>' +
           '<tbody>' + rows + '</tbody>' +
           '</table></div></div></div>';
}

function statCard(count, label, colorClass) {
    return '<div class="col-xs-4 col-sm-4">' +
           '<div class="panel panel-default stat-card">' +
           '<h4 class="' + colorClass + '">' + count + '</h4>' +
           '<small class="text-muted">' + label + '</small>' +
           '</div></div>';
}
</script>

<div class="content-box" style="padding:10px 15px 5px;">
    <button id="refreshBtn" class="btn btn-primary btn-sm">
        <i class="fa fa-refresh"></i> Refresh Now
    </button>
    <small class="text-muted" style="margin-left:12px;">Auto-refresh every 30 seconds</small>
</div>

<div id="configLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading Kea DHCP configuration...</p>
</div>

<div id="configError"  style="display:none; padding:10px;"></div>
<div id="configContent" style="display:none; padding:10px;"></div>
</content>

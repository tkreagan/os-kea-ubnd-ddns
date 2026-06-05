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
    .kea-subnet  { font-family: monospace; font-size: 0.9em; }
    .ku-topinfo .panel-body { padding: 8px 12px; }
    .ku-srclabel { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.04em;
                   color: #888; margin-bottom: 4px; }
    .ku-topinfo .ku-row { margin: 2px 0; }
    .ku-topinfo code { font-size: 0.85em; }
    /* Bootstrap renders <code> in crimson by default — use a muted slate and
       drop the white box so paths and addresses read inline without visual noise. */
    code { color: #5a7a9a; background: none; padding: 0; border: none; box-shadow: none; }
</style>

<script>
$( document ).ready(function() {
    loadKeaConfig();
    setInterval(function() {
        if ($("#autoRefreshCheck").is(":checked")) { loadKeaConfig(); }
    }, 30000);
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
                ? 'Request timed out — check that the Kea DHCP service is running'
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
    'tsig_mismatch': { label: 'TSIG Mismatch',   cls: 'label-warning'  },
    'wrong_target':  { label: 'Other Target',    cls: 'label-warning' },
    'no_ddns':       { label: 'No DDNS',         cls: 'label-default' },
    'd2_offline':    { label: 'DDNS Agent Down', cls: 'label-warning'  },
};

function bucketBadge(status) {
    const b = BUCKET_LABELS[status] || { label: status, cls: 'label-default' };
    return '<span class="label ' + b.cls + '">' + b.label + '</span>';
}

function connLine(label, conn) {
    if (!conn) return '';
    if (!conn.enabled) {
        const dot = '<i class="fa-regular fa-circle" title="disabled" style="color:#ccc; font-size:0.7em;"></i>';
        return '<div class="ku-row">' + dot + ' <strong>' + label + ':</strong> ' +
               '<span class="text-muted">service not enabled in Kea</span></div>';
    }
    let val;
    if (conn.method === 'unix') {
        val = '<span class="text-muted">unix socket:</span> <code>' + escapeHtml(conn.detail) + '</code>';
    } else if (conn.method === 'http') {
        val = '<span class="text-muted">HTTP:</span> <code>' + escapeHtml(conn.detail) + '</code>';
    } else {
        val = '<span class="text-muted">not resolved</span>';
    }
    const dot = conn.reachable
        ? '<i class="fa-solid fa-circle" title="reachable" style="color:#5cb85c; font-size:0.7em;"></i>'
        : '<i class="fa-regular fa-circle" title="not responding" style="color:#aaa; font-size:0.7em;"></i>';
    return '<div class="ku-row">' + dot + ' <strong>' + label + ':</strong> ' + val + '</div>';
}

function statusSection(data) {
    const kc = data.kea_control || {};
    const l  = data.our_listener;

    let html = '<div class="panel panel-default ku-topinfo" style="margin-bottom:12px;">' +
               '<div class="panel-heading" style="padding:8px 12px;">' +
               '<h4 class="panel-title" style="font-size:1em; font-weight:600;">Kea &amp; Listener Status</h4>' +
               '</div><div class="panel-body">';

    html += '<div class="ku-srclabel">Kea DHCP Control Channel</div>';
    html += connLine('DHCPv4', kc.dhcp4);
    html += connLine('DHCPv6', kc.dhcp6);

    html += '<div class="ku-srclabel" style="margin-top:10px;">Kea Unbound Plugin &mdash; DDNS Listener Status</div>';
    if (l) {
        const dot = l.running
            ? '<i class="fa-solid fa-circle" title="running" style="color:#5cb85c; font-size:0.7em;"></i>'
            : '<i class="fa-solid fa-circle" title="not running" style="color:#d9534f; font-size:0.7em;"></i>';
        const tsig = l.tsig_enabled
            ? '<span class="text-muted">TSIG on</span>'
            : '<span class="text-muted">no TSIG</span>';
        html += '<div class="ku-row">' + dot + ' <strong>Listening on:</strong> <code>' +
                escapeHtml(l.address) + ':' + l.port + '</code> &middot; ' + tsig + '</div>';
    }

    html += '</div></div>';
    return html;
}

function ddnsConfigTable(ok, wrong, tsig, no_ddns) {
    function row(count, label, color) {
        const dim = count === 0;
        return '<tr>' +
               '<td style="width:3em; text-align:right; padding:3px 0; font-size:1.3em; font-weight:bold; color:' +
               (dim ? '#ccc' : color) + ';">' + count + '</td>' +
               '<td style="padding:3px 0 3px 14px;' + (dim ? ' color:#bbb;' : '') + '">' + label + '</td>' +
               '</tr>';
    }
    return '<div class="panel panel-default" style="margin-bottom:12px;">' +
           '<div class="panel-heading" style="padding:8px 12px;">' +
           '<h4 class="panel-title" style="font-size:1em; font-weight:600;">Kea DDNS Forward Configuration Status</h4>' +
           '</div><div class="panel-body" style="padding:10px 14px;">' +
           '<table style="border-collapse:collapse;">' +
           row(ok,      'Kea-Unbound Configured Subnets',                  '#5cb85c') +
           row(tsig,    'Kea-Unbound Configured / TSIG Mismatch Subnets', '#f0ad4e') +
           row(wrong,   'Subnets configured for other zones',              '#f0ad4e') +
           row(no_ddns, 'No DDNS configuration',                          '#aaa') +
           '</table></div></div>';
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

    // ── Kea & Listener Status ─────────────────────────────────────────────────
    html += statusSection(data);

    // ── Kea DDNS Forward Configuration Status ────────────────────────────────
    html += ddnsConfigTable(ok, wrong, tsig, no_ddns);

    // ── Status alert ──────────────────────────────────────────────────────────
    if (total === 0) {
        html += '<div class="alert alert-info">No subnets found in Kea DHCP.</div>';
    } else if (ok !== total) {
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
        html += '<h5><span class="label label-warning">DDNS Agent Down</span> &nbsp;Start the Kea DHCP-DDNS daemon</h5>' +
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
                '<li>Set <strong>DNS forward zone</strong> to your domain (e.g. <code>home.example.com</code>)</li>' +
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
        html += '<h5><span class="label label-warning">TSIG Mismatch</span> &nbsp;Fix TSIG authentication</h5>' +
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

</script>

<div class="content-box" style="padding:10px 15px 5px;">
    <div style="display:flex; align-items:center;">
        <label style="margin:0; font-weight:normal; color:#777; cursor:pointer;">
            <input type="checkbox" id="autoRefreshCheck" checked style="margin-right:5px;">
            Auto-refresh every 30 seconds
        </label>
        <button id="refreshBtn" class="btn btn-primary btn-sm" style="margin-left:20px;">
            <i class="fa fa-refresh"></i> Refresh Now
        </button>
    </div>
</div>

<div id="configLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading Kea DHCP configuration...</p>
</div>

<div id="configError"  style="display:none; padding:10px;"></div>
<div id="configContent" style="display:none; padding:10px;"></div>
</content>

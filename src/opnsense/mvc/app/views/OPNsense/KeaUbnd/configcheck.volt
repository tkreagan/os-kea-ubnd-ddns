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
    /* Lightweight section divider used in place of panel headings for status rows. */
    .ku-section-label {
        font-size: 0.79em; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.07em; color: #b0b0b0;
        border-bottom: 1px solid #ebebeb;
        padding-bottom: 4px; margin: 16px 0 8px;
    }
    .ku-row { margin: 3px 0; }
    .ku-srclabel { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.04em;
                   color: #888; margin-bottom: 4px; }
    code { color: #5a7a9a; background: none; padding: 0; border: none; box-shadow: none; }
    .ku-timer-bar { height: 100%; background: rgba(0,0,0,0.22); width: 100%; transition: width 30s linear; }
</style>

<script>
$( document ).ready(function() {
    loadKeaConfig();
    setInterval(function() {
        if ($("#autoRefreshCheck").is(":checked")) { loadKeaConfig(); }
    }, 30000);
    $(document).on("click", "#refreshBtn", function() { loadKeaConfig(); });
});

function loadKeaConfig() {
    $("#configLoader").show();
    $("#configContent").hide();
    $("#configError").hide();

    $.ajax({
        url: '/api/keaubnd/config_check/check',
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
    // 'tsig_mismatch' kept so any subnet the server tags with it still renders a readable badge,
    // but TSIG is otherwise hidden from the UI (deferred feature — see listener row comment above).
    'tsig_mismatch': { label: 'TSIG Mismatch',   cls: 'label-warning'  },
    'wrong_target':  { label: 'Other Target',    cls: 'label-warning' },
    'no_ddns':       { label: 'No DDNS',         cls: 'label-default' },
    'd2_offline':    { label: 'DDNS Agent Down', cls: 'label-warning'  },
};

function bucketBadge(status) {
    const b = BUCKET_LABELS[status] || { label: status, cls: 'label-default' };
    return '<span class="label ' + b.cls + '">' + b.label + '</span>';
}

const KEA_LINKS = {
    dhcp4: [
        ['Subnets',      '/ui/kea/dhcpv4#subnets'],
        ['Reservations', '/ui/kea/dhcpv4#reservations'],
        ['Leases',       '/ui/kea/leases4'],
        ['Settings',     '/ui/kea/dhcpv4#settings'],
    ],
    dhcp6: [
        ['Subnets',      '/ui/kea/dhcpv6#subnets'],
        ['Reservations', '/ui/kea/dhcpv6#reservations'],
        ['Leases',       '/ui/kea/leases6'],
        ['Settings',     '/ui/kea/dhcpv6#settings'],
    ],
    d2: [
        ['Settings', '/ui/kea/ddns'],
    ],
};

function keaLinks(key) {
    const pairs = KEA_LINKS[key] || [];
    if (!pairs.length) return '';
    return '<span style="font-size:0.85em; font-weight:normal; text-transform:none; letter-spacing:0; color:#777;">' +
        pairs.map(function(p) {
            return '<a href="' + p[1] + '" target="_blank">' + p[0] + '</a>';
        }).join(' &nbsp;&middot;&nbsp; ') + '</span>';
}

function connLine(label, conn, linksKey) {
    if (!conn) return '';
    const links = keaLinks(linksKey);
    const hdr = '<div style="display:flex; align-items:center; justify-content:space-between;">';
    if (!conn.enabled) {
        const dot = '<i class="fa-regular fa-circle" title="disabled" style="color:#ccc; font-size:0.7em;"></i>';
        return hdr + '<div class="ku-row" style="margin:0;">' + dot + ' <strong>' + label + '</strong> &ensp;' +
               '<span class="text-muted">service not enabled in Kea</span></div>' + links + '</div>';
    }
    let val;
    if (conn.method === 'unix') {
        val = '<span class="text-muted">unix socket</span> <code>' + escapeHtml(conn.detail) + '</code>';
    } else if (conn.method === 'http') {
        val = '<span class="text-muted">HTTP</span> <code>' + escapeHtml(conn.detail) + '</code>';
    } else if (conn.manual_config) {
        val = '<span class="text-muted">manual config mode &mdash; socket not resolved</span>';
    } else {
        val = '<span class="text-muted">not resolved</span>';
    }
    const dot = conn.reachable
        ? '<i class="fa-solid fa-circle" title="reachable" style="color:#5cb85c; font-size:0.7em;"></i>'
        : '<i class="fa-regular fa-circle" title="not responding" style="color:#aaa; font-size:0.7em;"></i>';
    return hdr + '<div class="ku-row" style="margin:0;">' + dot + ' <strong>' + label + '</strong> &ensp;' + val + '</div>' +
           links + '</div>';
}

function manualConfigBanner(data) {
    const kc = data.kea_control || {};
    const services = ['dhcp4', 'dhcp6'].filter(s => kc[s] && kc[s].manual_config);
    if (services.length === 0) return '';
    const names = services.map(s => s === 'dhcp4' ? 'DHCPv4' : 'DHCPv6').join(' and ');
    return '<div class="alert alert-warning" style="margin-bottom:12px;">' +
           '<strong>Manual configuration mode active (' + names + ')</strong><br>' +
           'Kea is running with a hand-edited config file. The Config Check reads the live ' +
           'Kea configuration via <code>config-get</code> and interprets it as-is, but some ' +
           'checks assume OPNsense-managed config conventions (e.g. per-subnet ' +
           '<code>ddns-send-updates</code> rather than global inheritance). ' +
           'Results may be inaccurate for non-standard config structures. ' +
           'Verify DDNS registration independently.' +
           '</div>';
}

function pluginStatusSection(data, autoRefreshOn) {
    const l = data.our_listener;
    if (!l) return '';

    const dot = function(on) {
        return on
            ? '<i class="fa-solid fa-circle" style="color:#5cb85c; font-size:0.7em;"></i>'
            : '<i class="fa-solid fa-circle" style="color:#d9534f; font-size:0.7em;"></i>';
    };

    const chk = (autoRefreshOn !== false) ? ' checked' : '';
    const controls = '<span style="font-size:1em; font-weight:normal; text-transform:none; letter-spacing:0; color:#777; display:inline-flex; align-items:center; gap:10px;">' +
        '<label style="margin:0; font-weight:normal; cursor:pointer; display:inline-flex; align-items:center; gap:4px;">' +
        '<input type="checkbox" id="autoRefreshCheck"' + chk + ' style="margin:0;">' +
        'Auto-refresh</label>' +
        '<button id="refreshBtn" class="btn btn-default btn-xs">' +
        '<i class="fa fa-refresh"></i> Refresh Now</button></span>';

    let html = '<div class="ku-section-label" style="margin-top:0; display:flex; align-items:center; justify-content:space-between;">' +
               '<span>Plugin Daemons</span>' + controls + '</div>';

    // TSIG status removed from display (deferred feature — listener binds to 127.0.0.1 so
    // unsigned updates are safe; TSIG only matters if listen address is exposed beyond localhost).
    // To restore: l.tsig_enabled was shown as "TSIG on" / "no TSIG" after the address:port here.
    html += '<div class="ku-row">' + dot(l.running) +
            ' <strong>DDNS Listener</strong> &ensp;' +
            '<code>' + escapeHtml(l.address) + ':' + l.port + '</code></div>';

    if (l.logwatcher_enabled) {
        const logging = l.logwatcher_logging || {};
        let loggingNote = '';
        if (logging.ok === true) {
            loggingNote = ' &ensp;<span class="text-muted" style="font-size:0.88em;">' +
                          escapeHtml(logging.detail) + '</span>';
        } else if (logging.ok === false) {
            loggingNote = ' &ensp;<span style="color:#e0a800; font-size:0.88em;">' +
                          '<i class="fa fa-exclamation-triangle"></i> ' +
                          escapeHtml(logging.detail) + '</span>';
        }
        if (l.logwatcher_running) {
            html += '<div class="ku-row"><i class="fa-solid fa-circle" style="color:#5cb85c; font-size:0.7em;"></i>' +
                    ' <strong>Log Watcher</strong>' + loggingNote + '</div>';
        } else {
            html += '<div class="ku-row"><i class="fa-solid fa-circle" style="color:#d9534f; font-size:0.7em;"></i>' +
                    ' <strong>Log Watcher</strong> &ensp;<span class="text-muted">not running</span>' + loggingNote + '</div>';
        }
    } else {
        // Hollow green: off by design, not a problem.
        html += '<div class="ku-row"><i class="fa-regular fa-circle" style="color:#5cb85c; font-size:0.7em;"></i>' +
                ' <strong>Log Watcher</strong> &ensp;<span class="text-muted">disabled</span></div>';
    }

    (data.ha_advisories || []).forEach(function(a) {
        html += '<div class="ku-row" style="margin-top:6px;">' +
                '<i class="fa fa-exclamation-triangle" style="color:#e0a800;"></i> ' +
                '<strong>' + escapeHtml(a.heading) + '</strong> &ensp;' +
                '<span class="text-muted">' + escapeHtml(a.message) + '</span></div>';
    });

    return html;
}

function statusSection(data) {
    const kc = data.kea_control || {};
    let html = '<div class="ku-section-label">Kea DHCP</div>';
    html += connLine('DHCPv4', kc.dhcp4, 'dhcp4');
    html += connLine('DHCPv6', kc.dhcp6, 'dhcp6');

    // D2 (kea-dhcp-ddns) status.
    const d2Dot = data.d2_reachable
        ? '<i class="fa-solid fa-circle" style="color:#5cb85c; font-size:0.7em;"></i>'
        : '<i class="fa-regular fa-circle" style="color:#aaa; font-size:0.7em;"></i>';
    const d2Text = data.d2_reachable
        ? '<span class="text-muted">forward zones configured</span>'
        : '<span class="text-muted">not running or no forward zones configured</span>';
    html += '<div style="display:flex; align-items:center; justify-content:space-between;">' +
            '<div class="ku-row" style="margin:0;">' + d2Dot + ' <strong>DDNS Agent (d2)</strong> &ensp;' + d2Text + '</div>' +
            keaLinks('d2') + '</div>';

    return html;
}

// TSIG mismatch row removed from this table (deferred feature).
// To restore: add tsig param and row(tsig, 'Kea-Unbound Configured / TSIG Mismatch Subnets', '#f0ad4e')
// after the ok row. Also restore tsig count in renderKeaConfig and hasTsig in fixGuide.
function ddnsConfigTable(ok, wrong, no_ddns) {
    function row(count, label, color) {
        const dim = count === 0;
        return '<tr>' +
               '<td style="width:3em; text-align:right; padding:3px 0; font-size:1.3em; font-weight:bold; color:' +
               (dim ? '#ccc' : color) + ';">' + count + '</td>' +
               '<td style="padding:3px 0 3px 14px;' + (dim ? ' color:#bbb;' : '') + '">' + label + '</td>' +
               '</tr>';
    }
    return '<div style="margin-top:10px;">' +
           '<table style="border-collapse:collapse;">' +
           row(ok,      'Configured for Kea Unbound DDNS',     '#5cb85c') +
           row(wrong,   'Configured for other DDNS servers',  '#f0ad4e') +
           row(no_ddns, 'No DDNS configured',                 '#aaa') +
           '</table></div>';
}

// ── Unbound DNS Configuration section ────────────────────────────────────────
function unboundSection(data) {
    const checks   = data.unbound_checks || [];
    const uRunning = data.unbound_running !== false;
    const uDot = uRunning
        ? '<i class="fa-solid fa-circle" style="color:#5cb85c; font-size:0.7em;"></i>'
        : '<i class="fa-solid fa-circle" style="color:#d9534f; font-size:0.7em;"></i>';
    const uStatus = uRunning
        ? (checks.length === 0
            ? '<span class="text-muted">running &middot; no issues</span>'
            : '<span class="text-muted">running</span>')
        : '<span class="text-muted">not running</span>';

    let body = '<div class="ku-row">' + uDot + ' <strong>DNS Resolver</strong> &ensp;' + uStatus + '</div>';

    checks.forEach(function(c) {
        const isWarn   = c.level === 'warning';
        const alertCls = isWarn ? 'alert-warning' : 'alert-info';
        const icon     = isWarn ? 'fa-exclamation-triangle' : 'fa-info-circle';
        let fixBtn = '';
        if (c.fixable && c.id === 'regdhcpstatic') {
            fixBtn = ' <button class="btn btn-xs btn-default" id="btn_fix_regdhcpstatic" style="margin-left:8px;">' +
                     '<i class="fa fa-wrench"></i> Disable &amp; Restart Unbound</button>';
        }
        body += '<div class="alert ' + alertCls + '" style="margin-bottom:8px; padding:8px 12px;">' +
                '<strong><i class="fa ' + icon + '"></i> ' + escapeHtml(c.heading) + ':</strong> ' +
                escapeHtml(c.message) + fixBtn + '</div>';
    });

    const unboundLinks = '<span style="font-size:1em; font-weight:normal; text-transform:none; letter-spacing:0;">' +
        '<a href="/ui/unbound/overrides" target="_blank">Overrides</a>' +
        ' &nbsp;&middot;&nbsp; ' +
        '<a href="/ui/unbound/general" target="_blank">Settings</a></span>';

    return '<div class="ku-section-label" style="display:flex; align-items:center; justify-content:space-between;">' +
           '<span>Unbound DNS</span>' + unboundLinks + '</div>' + body;
}

function bindUnboundButtons() {
    $("#btn_fix_regdhcpstatic").off('click').on('click', function() {
        const $btn = $(this);
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
        $.ajax({
            url: '/api/keaubnd/config_check/disable_regdhcpstatic',
            type: 'POST',
            contentType: 'application/json',
            dataType: 'json',
            data: JSON.stringify({}),
            timeout: 30000,
            success: function(resp) {
                if (resp.status === 'ok') {
                    loadKeaConfig();
                } else {
                    $btn.prop('disabled', false).html('<i class="fa fa-wrench"></i> Disable &amp; Restart Unbound');
                    alert('Error: ' + (resp.message || 'unknown error'));
                }
            },
            error: function() {
                $btn.prop('disabled', false).html('<i class="fa fa-wrench"></i> Disable &amp; Restart Unbound');
                alert('Request failed.');
            }
        });
    });
}

function renderKeaConfig(data) {
    window._kuListenerPort = data.our_listener ? data.our_listener.port : 53535;
    window._kuKcData = data.kea_control || {};
    const v4  = data.ipv4_subnets || [];
    const v6  = data.ipv6_subnets || [];
    const all = v4.concat(v6);

    const ok       = all.filter(s => s.ddns_status === 'ok').length;
    const wrong    = all.filter(s => s.ddns_status === 'wrong_target').length;
    const no_ddns  = all.filter(s => s.ddns_status === 'no_ddns').length;
    const d2_off   = all.filter(s => s.ddns_status === 'd2_offline').length;
    // tsig count removed (TSIG deferred) — const tsig = all.filter(s => s.ddns_status === 'tsig_mismatch').length;
    const total    = all.length;
    const problems = total - ok;

    // Preserve checkbox state across re-renders (element may not exist on first render).
    const autoRefreshOn = !$("#autoRefreshCheck").length || $("#autoRefreshCheck").is(":checked");

    let html = '';

    // ── Plugin Daemons (listener + logwatcher) ────────────────────────────────
    html += pluginStatusSection(data, autoRefreshOn);

    // ── Unbound DNS ───────────────────────────────────────────────────────────
    html += unboundSection(data);

    // ── Kea DHCP status (control channels + D2) ──────────────────────────────
    html += statusSection(data);

    // ── Subnet Configuration ──────────────────────────────────────────────────
    if (total > 0) {
        const port = data.our_listener ? data.our_listener.port : 53535;
        const applyAll = '<span style="font-size:1em; font-weight:normal; text-transform:none; letter-spacing:0;">' +
            '<button id="btn_push_all" class="btn btn-primary btn-xs"' +
            ' title="Sets DDNS server to 127.0.0.1:' + port + ', enables override flags, and restarts Kea">' +
            '<i class="fa-solid fa-wand-magic-sparkles"></i> Configure All Subnets for Kea Unbound DDNS</button></span>';
        html += '<div class="ku-section-label" style="display:flex; align-items:center; justify-content:space-between;">' +
                '<span>Subnet Configuration</span>' + applyAll + '</div>';
    } else {
        html += '<div class="ku-section-label">Subnet Configuration</div>';
    }
    html += '<div id="ku-push-result"></div>';
    html += manualConfigBanner(data);
    html += ddnsConfigTable(ok, wrong, no_ddns);
    html += summaryAdvisoriesHtml(data.summary_advisories);

    if (total === 0) {
        html += '<div class="alert alert-info" style="margin-top:10px;">No subnets found in Kea DHCP.</div>';
    }

    // ── Subnet tables ─────────────────────────────────────────────────────────
    html += '<div style="margin-top:14px;">';
    html += subnetPanel('IPv4 Subnets', v4);
    html += subnetPanel('IPv6 Subnets', v6);
    html += '</div>';

    // ── Contextual fix instructions ───────────────────────────────────────────
    if (problems > 0) {
        html += fixGuide(wrong > 0, no_ddns > 0, d2_off > 0, data.our_listener);
    }

    $("#configContent").html(html);

    // Restore any pending push-result banner (set before loadKeaConfig re-rendered us).
    if (window._kuPendingBanner) {
        showPushResultBanner(window._kuPendingBanner);
        window._kuPendingBanner = null;
    }

    // Wire actions (content is rebuilt each refresh, so bind every time).
    bindUnboundButtons();
    $("#btn_push_all").off('click').on('click', openPushAllModal);
    $(".ku-push-subnet").off('click').on('click', function() {
        openPushSubnetModal($(this));
    });
}

// ── Push: ephemeral result banner ─────────────────────────────────────────────
// Banner lives at the top of the Subnet Configuration section.  It auto-
// dismisses after 30 s with a draining timer bar so the user can see it's
// transient.  Re-renders (auto-refresh) clear it naturally; _kuPendingBanner
// carries state across the loadKeaConfig() that follows every successful push.

function showPushResultBanner(state) {
    const $el = $('#ku-push-result');
    if (!$el.length) return;
    clearTimeout(window._kuBannerTimer);
    $el.stop(true, true).show().html(pushBannerHtml(state));
    // Trigger the CSS drain transition one frame after paint so the initial
    // width:100% is visible before we animate to 0%.
    requestAnimationFrame(function() {
        $el.find('.ku-timer-bar').css('width', '0%');
    });
    window._kuBannerTimer = setTimeout(function() {
        $el.fadeOut(800, function() { $el.empty().show(); });
    }, 30000);
}

function pushBannerHtml(state) {
    const data   = state.data;
    const changed = data.changed || [];
    const skipped = data.skipped || [];
    const mc      = data.manual_config_skipped || [];
    const errors  = data.errors  || [];

    // Determine alert colour.
    let type = changed.length ? 'success' : 'info';
    if (errors.length)                       type = 'danger';
    else if (mc.length && !changed.length)   type = 'warning';
    else if (mc.length || skipped.length)    type = changed.length ? 'success' : 'warning';

    // Build headline.
    let headline = '';
    if (changed.length) {
        const list = '<span class="kea-subnet">' + changed.map(escapeHtml).join(', ') + '</span>';
        headline = 'Applied to ' + changed.length + ' subnet' + (changed.length !== 1 ? 's' : '') +
                   ': ' + list + '. Kea restarted.';
    }

    // Build footnotes.
    const notes = [];
    if (mc.length) {
        const names = mc.map(function(s) { return s === 'dhcp4' ? 'DHCPv4' : 'DHCPv6'; }).join(' and ');
        notes.push(names + ': manual config — edit kea-dhcp-ddns.conf directly');
    }
    if (skipped.length) {
        notes.push(skipped.length + ' subnet' + (skipped.length !== 1 ? 's' : '') + ' skipped (no resolvable domain)');
    }
    if (errors.length) {
        notes.push(errors.map(function(e) { return escapeHtml(e.subnet) + ': ' + escapeHtml(e.message); }).join('; '));
    }

    if (!headline && !notes.length) {
        headline = 'No changes — subnets already configured.';
    } else if (!headline) {
        headline = notes.shift();
    }

    let body = '<strong>' + headline + '</strong>';
    if (notes.length) {
        body += '<span style="display:block; margin-top:3px; font-size:0.88em; color:#555;">' +
                notes.join('<br>') + '</span>';
    }

    const closeBtn =
        '<button type="button" onclick="clearTimeout(window._kuBannerTimer);$(this).closest(\'[id=ku-push-result]\').empty();" ' +
        'style="float:right; margin:-2px -4px 0 8px; background:none; border:none; font-size:1.3em; line-height:1; cursor:pointer; color:inherit; opacity:0.6;">' +
        '&times;</button>';

    return '<div class="alert alert-' + type + '" ' +
           'style="margin:0 0 8px; padding:8px 12px 5px; position:relative; overflow:hidden;">' +
           closeBtn + body +
           '<div style="position:absolute; bottom:0; left:0; right:0; height:3px;">' +
           '<div class="ku-timer-bar"></div></div>' +
           '</div>';
}

// ── Push: shared change-list shown in both modals ─────────────────────────────
function changeListHtml(port) {
    return '<ul style="padding-left:18px; margin-bottom:8px;">' +
           '<li>DNS server → <code>127.0.0.1</code>, port → <code>' + port + '</code> (enables DDNS)</li>' +
           '<li>Override no-update, Override client-update, Update-on-renew → <strong>on</strong></li>' +
           '<li>Conflict resolution → <code>no-check-without-dhcid</code></li>' +
           '<li>Reverse DNS zones are <strong>not</strong> changed</li>' +
           '</ul>';
}

function getListenerPort() {
    // Cached from the last successful check render.
    return window._kuListenerPort || 53535;
}

// ── Push: per-subnet modal ────────────────────────────────────────────────────
function openPushSubnetModal($btn) {
    const port      = getListenerPort();
    const uuid      = $btn.data('uuid');
    const service   = $btn.data('service');
    const cidr      = String($btn.data('cidr'));
    const suffixSet = String($btn.data('suffixset')) === '1';
    const basis     = $btn.data('basis') ? String($btn.data('basis')) : '';
    const source    = $btn.data('source') ? String($btn.data('source')) : '';

    let caption;
    if (suffixSet) {
        caption = 'Using the subnet\'s existing qualifying suffix — it will not be changed.';
    } else if (source === 'option15') {
        caption = 'Default from DHCP option 15 (domain-name) handed to clients on this subnet.';
    } else if (source === 'option24') {
        caption = 'Default from DHCP option 24 (domain-search) handed to clients on this subnet.';
    } else if (source === 'system') {
        caption = 'Default from the OPNsense system domain (subnet has no domain configured).';
    } else {
        caption = 'No domain is configured for this subnet — enter one to apply.';
    }

    $("#push_subnet_title").text('Apply Recommended Settings — ' + cidr);
    $("#push_subnet_changes").html(changeListHtml(port));
    $("#push_subnet_caption").text(caption);
    $("#push_subnet_domain").val(basis).prop('readonly', suffixSet);
    $("#push_subnet_domain_group").toggle(!suffixSet || basis !== '');
    $("#push_subnet_result").empty();

    // Stash request params on the confirm button.
    $("#push_subnet_confirm").data('uuid', uuid)
                             .data('service', service)
                             .data('cidr', cidr)
                             .data('suffixset', suffixSet ? 1 : 0)
                             .prop('disabled', false)
                             .text('Apply & Restart Kea');
    $("#modal_push_subnet").modal('show');
}

function confirmPushSubnet() {
    const $btn      = $("#push_subnet_confirm");
    const suffixSet = String($btn.data('suffixset')) === '1';
    const domain    = $.trim($("#push_subnet_domain").val());
    if (!suffixSet && domain === '') {
        $("#push_subnet_result").html(
            '<div class="alert alert-danger" style="margin:8px 0 0;">Enter a domain to apply.</div>');
        return;
    }
    const payload = {
        scope:   'subnet',
        service: $btn.data('service'),
        uuid:    $btn.data('uuid')
    };
    // Only send a domain override when the suffix is empty (we never overwrite).
    if (!suffixSet && domain !== '') { payload.domain = domain; }
    doPush(payload, $btn, $("#push_subnet_result"), "#modal_push_subnet");
}

// ── Push: all-subnets modal ───────────────────────────────────────────────────
function openPushAllModal() {
    const port = getListenerPort();
    $("#push_all_changes").html(changeListHtml(port));
    $("#push_all_result").empty();
    $("#push_all_confirm").prop('disabled', false).text('Apply to All & Restart Kea');
    $("#modal_push_all").modal('show');
}

function confirmPushAll() {
    doPush({ scope: 'all' }, $("#push_all_confirm"), $("#push_all_result"), "#modal_push_all");
}

// ── Push: shared AJAX + result rendering ──────────────────────────────────────
function doPush(payload, $btn, $result, modalSel) {
    $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
    $result.empty();
    $.ajax({
        url: '/api/keaubnd/config_check/push_settings',
        type: 'POST',
        contentType: 'application/json',
        dataType: 'json',
        data: JSON.stringify(payload),
        timeout: 60000,
        success: function(data) {
            // Structured response (has a 'changed' array) → close modal, show
            // ephemeral banner in the section.  Plain error messages stay in
            // the modal so the user can read them before dismissing.
            if (Array.isArray(data.changed)) {
                $(modalSel).modal('hide');
                window._kuPendingBanner = { data: data, scope: payload.scope };
                loadKeaConfig();
            } else {
                $result.html(pushResultHtml(data));
                $btn.prop('disabled', false).text('Retry');
            }
        },
        error: function(xhr, status) {
            $result.html('<div class="alert alert-danger" style="margin:8px 0 0;">' +
                'Request failed' + (status === 'timeout' ? ' (timed out)' : '') + '.</div>');
            $btn.prop('disabled', false).text('Retry');
        }
    });
}

function pushResultHtml(data) {
    if (data.status === 'error' && data.message) {
        return '<div class="alert alert-danger" style="margin:8px 0 0;">' +
               escapeHtml(data.message) + '</div>';
    }
    let h = '';
    const changed = data.changed || [];
    const skipped = data.skipped || [];
    const errors  = data.errors  || [];
    if (changed.length) {
        h += '<div class="alert alert-success" style="margin:8px 0 0;">Applied to ' +
             changed.length + ' subnet' + (changed.length !== 1 ? 's' : '') +
             ': <span class="kea-subnet">' + changed.map(escapeHtml).join(', ') +
             '</span>. Kea restarted.</div>';
    }
    if (skipped.length) {
        h += '<div class="alert alert-warning" style="margin:8px 0 0;"><strong>Skipped:</strong><ul style="margin:4px 0 0; padding-left:18px;">' +
             skipped.map(function(s) {
                 return '<li><span class="kea-subnet">' + escapeHtml(s.subnet) + '</span> — ' +
                        escapeHtml(s.reason) + '</li>';
             }).join('') + '</ul></div>';
    }
    if (errors.length) {
        h += '<div class="alert alert-danger" style="margin:8px 0 0;"><strong>Errors:</strong><ul style="margin:4px 0 0; padding-left:18px;">' +
             errors.map(function(e) {
                 return '<li>' + escapeHtml(e.subnet) + ': ' + escapeHtml(e.message) + '</li>';
             }).join('') + '</ul></div>';
    }
    return h || '<div class="alert alert-info" style="margin:8px 0 0;">No changes.</div>';
}

// TSIG section removed from fixGuide (deferred feature). To restore: add hasTsig param and this block:
//   if (hasTsig) {
//     html += '<h5><span class="label label-warning">TSIG Mismatch</span> &nbsp;Fix TSIG authentication</h5>' +
//             '<p>Both sides must agree on TSIG — either both enabled with matching key, or both disabled.</p>' +
//             '<strong>To enable TSIG on this subnet:</strong><ol>' +
//             '<li>Click <strong>Advanced</strong> in the Dynamic DNS section</li>' +
//             '<li>Set <strong>TSIG key name</strong> to match the plugin\'s key name (Settings tab)</li>' +
//             '<li>Set <strong>TSIG secret</strong> to the same base64-encoded secret</li>' +
//             '<li>Set <strong>TSIG algorithm</strong> to match (e.g. HMAC-SHA256)</li>' +
//             '<li>Save and Apply</li></ol>' +
//             '<strong>To disable TSIG instead:</strong> go to the Kea Unbound Settings tab and uncheck ' +
//             '<em>Enable TSIG authentication</em>, then Apply.';
//   }
function fixGuide(hasWrong, hasNoDdns, hasD2Off, listener) {
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
            'to reveal the port field. Apply after saving.</p>';

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

    html += '</div></div></div>';
    return html;
}

function summaryAdvisoriesHtml(advisories) {
    if (!advisories || !advisories.length) return '';
    return advisories.map(function(a) {
        const warn = a.level === 'warning';
        const cls  = warn ? 'alert-warning' : 'alert-info';
        const icon = warn ? 'fa-exclamation-triangle' : 'fa-info-circle';
        return '<div class="alert ' + cls + '" style="margin-bottom:8px;">' +
               '<strong><i class="fa ' + icon + '"></i> ' + escapeHtml(a.heading) + ':</strong> ' +
               escapeHtml(a.message) + '</div>';
    }).join('');
}

function advisoriesHtml(arr) {
    if (!arr || !arr.length) { return ''; }
    let h = '';
    arr.forEach(function(a) {
        const warn = a.level === 'warning';
        const icon = warn
            ? '<i class="fa fa-exclamation-triangle"></i> '
            : '<i class="fa fa-info-circle"></i> ';
        const color = warn ? '#8a6d3b' : '#31708f';
        h += '<div style="margin-top:4px; font-size:0.85em; color:' + color + ';">' +
             icon + escapeHtml(a.message) + '</div>';
    });
    return h;
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
                '<td class="text-muted" style="font-size:0.9em;">' + escapeHtml(s.detail || '') + advisoriesHtml(s.advisories) + '</td>' +
                '<td>'                     + target                      + '</td>' +
                '<td>'                     + comment                     + '</td>' +
                '<td style="text-align:right;">' + pushButton(s)         + '</td>' +
                '</tr>';
    });

    return '<div class="panel panel-default" style="margin-bottom:12px;">' +
           '<div class="panel-heading"><h4 class="panel-title">' + title +
           ' (' + subnets.length + ')</h4></div>' +
           '<div class="panel-body" style="padding:0;">' +
           '<div class="table-responsive">' +
           '<table class="table table-striped table-condensed" style="margin:0;">' +
           '<thead><tr><th>Subnet</th><th>Status</th><th>Detail</th><th>DNS Target</th><th>Comment</th><th></th></tr></thead>' +
           '<tbody>' + rows + '</tbody>' +
           '</table></div></div></div>';
}

// Per-subnet "Apply" button. Disabled when the subnet has no matching config.xml
// node (no UUID) — without it the push has nothing to write to.
function pushButton(s) {
    const kc = (window._kuKcData || {})[s.service] || {};
    if (kc.manual_config) {
        return '<button class="btn btn-xs btn-default" disabled ' +
               'title="Kea ' + escapeHtml(s.service === 'dhcp6' ? 'DHCPv6' : 'DHCPv4') + ' is in manual configuration mode — edit the config file directly">Configure for Kea Unbound DDNS</button>';
    }
    if (!s.opnsense_uuid) {
        return '<button class="btn btn-xs btn-default" disabled ' +
               'title="No matching OPNsense subnet found">Configure for Kea Unbound DDNS</button>';
    }
    const data =
        " data-uuid='"   + escapeHtml(s.opnsense_uuid) + "'" +
        " data-service='" + escapeHtml(s.service || '') + "'" +
        " data-cidr='"   + escapeHtml(s.subnet) + "'" +
        " data-suffixset='" + (s.suffix_set ? '1' : '0') + "'" +
        " data-basis='"  + escapeHtml(s.domain_basis || '') + "'" +
        " data-source='" + escapeHtml(s.domain_source || '') + "'";
    return '<button class="btn btn-xs btn-primary ku-push-subnet"' + data + '>' +
           '<i class="fa-solid fa-wand-magic-sparkles"></i> Configure for Kea Unbound DDNS</button>';
}

</script>

<div id="configLoader" class="content-box" style="text-align:center; padding:20px; display:none;">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
    <p class="text-muted" style="margin-top:8px;">Loading Kea DHCP configuration...</p>
</div>

<div id="configError"  style="display:none; padding:10px;"></div>
<div id="configContent" style="display:none; padding:10px;"></div>

<!-- ── Apply Recommended Settings: single subnet ──────────────────────────── -->
<div class="modal fade" id="modal_push_subnet" tabindex="-1" role="dialog">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
        <h4 class="modal-title" id="push_subnet_title">Apply Recommended Settings</h4>
      </div>
      <div class="modal-body">
        <p class="text-muted">This writes the recommended DDNS settings to this subnet:</p>
        <div id="push_subnet_changes"></div>
        <div id="push_subnet_domain_group" class="form-group">
          <label for="push_subnet_domain">Domain (qualifying suffix &amp; forward zone)</label>
          <input type="text" class="form-control" id="push_subnet_domain" placeholder="e.g. home.example.com">
          <span class="help-block" id="push_subnet_caption" style="margin-bottom:0;"></span>
        </div>
        <div class="alert alert-warning" style="margin-bottom:0;">
          <i class="fa fa-exclamation-triangle"></i> Kea will be restarted when you apply.
        </div>
        <div id="push_subnet_result"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary" id="push_subnet_confirm" onclick="confirmPushSubnet();">Apply &amp; Restart Kea</button>
      </div>
    </div>
  </div>
</div>

<!-- ── Apply Recommended Settings: all subnets ────────────────────────────── -->
<div class="modal fade" id="modal_push_all" tabindex="-1" role="dialog">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
        <h4 class="modal-title">Apply Recommended Settings to All Subnets</h4>
      </div>
      <div class="modal-body">
        <p class="text-muted">This writes the recommended DDNS settings to every subnet:</p>
        <div id="push_all_changes"></div>
        <p class="text-muted" style="font-size:0.9em;">
          Subnets that already have a qualifying suffix or forward zone keep them unchanged.
          Subnets missing them get a domain from DHCP option 15 (domain-name), falling back to the
          OPNsense system domain. Subnets with no resolvable domain are skipped and listed below.
        </p>
        <div class="alert alert-warning" style="margin-bottom:0;">
          <i class="fa fa-exclamation-triangle"></i> Kea will be restarted when you apply.
        </div>
        <div id="push_all_result"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary" id="push_all_confirm" onclick="confirmPushAll();">Apply to All &amp; Restart Kea</button>
      </div>
    </div>
  </div>
</div>
</content>

<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Thomas Reagan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * keaunbound.inc -- OPNsense plugin hooks for os-kea-unbound.
 *
 * Hooks (registered in keaunbound_configure()):
 *
 *   kea_start / kea_sync / unbound_start -> keaunbound_sync_if_enabled()
 *       Register Kea static reservations and/or active leases into Unbound via
 *       reservation-sync.py / lease-sync.py. Gated on the plugin being enabled
 *       and on the per-feature toggles (static reservations additionally require
 *       Unbound's regdhcpstatic to be OFF, so we don't fight OPNsense over
 *       host_entries.conf). Tied to Unbound's lifecycle because Unbound holds
 *       the records: an Unbound reload wipes runtime local_data, so we
 *       repopulate on unbound_start.
 *
 *   bootup (priority 2) -> keaunbound_start_do()
 *       Start the RFC 2136 stub listener daemon via the 'keaunbound start'
 *       configd action, ordered after Unbound (bootup priority 1).
 *
 * Service / schedule / logging hooks:
 *   keaunbound_services() -- register the daemon for service control
 *   keaunbound_cron()     -- declare the auto-clean schedule (OPNsense cron)
 *   keaunbound_syslog()   -- register the 'kea-ub' log facility
 */

/**
 * Log a plugin error to syslog under the shared 'kea-ub' program tag so PHP
 * error paths land in the keaunbound log alongside the daemon and Python tools.
 */
function keaunbound_log_error($message)
{
    openlog('kea-ub', LOG_PID, LOG_DAEMON);
    syslog(LOG_ERR, $message);
    closelog();
}

function keaunbound_syslog()
{
    // Key must be a valid syslog-ng identifier (no hyphens). The template
    // generates filter/destination names like f_local_keaunbound and routes
    // logs to /var/log/keaunbound/keaunbound_YYYYMMDD.log.
    // The facility list is the syslog program tag shared by every component
    // (daemon, Python sync/audit/clean tools, start.py, and PHP error paths).
    // It must avoid the substring "unbound" — the core resolver filter is
    // program("unbound") and matches it as a substring — hence 'kea-ub'.
    return ['keaunbound' => ['facility' => [
        'kea-ub',
    ]]];
}

function keaunbound_services()
{
    $services = [];

    $cfg = new \OPNsense\KeaUnbound\General();
    if (empty((string)$cfg->general->enabled)) {
        return $services;
    }

    $services[] = [
        'configd' => [
            'restart' => ['keaunbound restart'],
            'start'   => ['keaunbound start'],
            'stop'    => ['keaunbound stop'],
        ],
        'name'        => 'kea-unbound-ddns',
        'description' => gettext('Kea Unbound DDNS registration'),
        'pidfile'     => '/var/run/kea-unbound-ddns.pid',
    ];

    return $services;
}

function keaunbound_cron()
{
    /*
     * Register the auto-clean cron job the OPNsense way.
     *
     * plugins_cron() collects this hook's return value and reconciles it into
     * the cron model (OPNsense/cron/jobs) by origin, which the Cron template
     * renders into the managed crontab. There is no file to write and no
     * teardown to perform: when the feature is disabled we simply return no
     * jobs, and the next cron rebuild drops the entry. The rebuild is triggered
     * by 'cron restart' (issued from reconfigureAction) and on boot.
     *
     * The job invokes the existing [clean] configd action so the schedule and
     * the GUI "Clean" button share one code path.
     */
    $jobs = [];

    $cfg = new \OPNsense\KeaUnbound\General();
    if (!empty((string)$cfg->general->enabled) && !empty((string)$cfg->general->enable_auto_clean)) {
        $hour_by_interval = [
            'h6'  => '0,6,12,18',
            'h12' => '0,12',
            'h24' => '0',
        ];
        $hour = $hour_by_interval[(string)$cfg->general->auto_clean_interval] ?? '0,6,12,18';

        // autocron format: [command, minute, hour, mday, month, wday] (trailing => *)
        $jobs[]['autocron'] = [
            '/usr/local/sbin/configctl -d keaunbound clean',
            '0',
            $hour,
        ];
    }

    return $jobs;
}

function keaunbound_configure()
{
    return [
        'kea_start'     => ['keaunbound_sync_if_enabled:2'],
        'kea_sync'      => ['keaunbound_sync_if_enabled:2'],
        'unbound_start' => ['keaunbound_sync_if_enabled'],
        'bootup'        => ['keaunbound_start_do:2'],
    ];
}

function keaunbound_sync_if_enabled($verbose = false)
{
    /*
     * Sync Kea data to Unbound if configured to do so.
     * Called from three hooks: kea_start, kea_sync, unbound_start.
     *
     * Syncs static reservations and/or dynamic leases depending on
     * plugin configuration. Returns 0 if all enabled syncs succeeded,
     * 1 if any enabled sync failed.
     */

    // Check if the overall KeaUnbound plugin is enabled
    $cfg = new \OPNsense\KeaUnbound\General();
    if (empty((string)$cfg->general->enabled)) {
        service_log("KeaUnbound: plugin disabled -- skipping sync\n", $verbose);
        return 0;
    }

    $errors = 0;

    if (should_sync_static_reservations()) {
        service_log('KeaUnbound: syncing static reservations...', $verbose);
        if (keaunbound_reservation_sync($verbose) != 0) {
            $errors++;
        }
    } else {
        service_log("KeaUnbound: static reservation sync disabled\n", $verbose);
    }

    if (should_sync_dynamic_leases()) {
        service_log('KeaUnbound: syncing active leases...', $verbose);
        if (keaunbound_lease_sync($verbose) != 0) {
            $errors++;
        }
    } else {
        service_log("KeaUnbound: dynamic lease sync disabled\n", $verbose);
    }

    return ($errors > 0) ? 1 : 0;
}

/**
 * Check if static reservations should be synced from Kea.
 *
 * Gated solely on the plugin's own sync_static_reservations toggle. We do NOT
 * consult Unbound's regdhcpstatic ("Register DHCP Static Mappings"): the real
 * conflict-guard is the host_entries.conf skip in reservation-sync.py, which
 * never touches a name OPNsense already wrote. So whether regdhcpstatic is on
 * or off, the plugin only fills the gap for reservations OPNsense hasn't
 * registered — and a reservation only becomes a host_entries entry via an
 * Unbound reconfigure, which wipes the plugin's runtime record anyway. There is
 * never a moment a name is registered twice: it's a live record (plugin) XOR a
 * config-persistent override (OPNsense), never both.
 */
function should_sync_static_reservations()
{
    $config = \OPNsense\Core\Config::getInstance();
    $keaunbound_static_xpath = $config->object()->xpath('OPNsense/KeaUnbound/general/sync_static_reservations');
    return !empty($keaunbound_static_xpath) && (string)$keaunbound_static_xpath[0] === '1';
}

/**
 * Check if dynamic leases should be synced from Kea.
 */
function should_sync_dynamic_leases()
{
    $config = \OPNsense\Core\Config::getInstance();

    // Get KeaUnbound plugin setting
    $keaunbound_dynamic_xpath = $config->object()->xpath('OPNsense/KeaUnbound/general/sync_dynamic_leases');

    return !empty($keaunbound_dynamic_xpath) && (string)$keaunbound_dynamic_xpath[0] === '1';
}

function keaunbound_reservation_sync($verbose = false)
{
    /*
     * Sync Kea static reservations to Unbound via reservation-sync.py.
     * Reads static reservations from Kea config via kea-ctrl-agent REST API
     * and registers each one in Unbound via unbound-control local_data.
     *
     * Respects guard against clobbering OPNsense-managed entries -- skips
     * any reservation whose hostname is in host_entries.conf.
     *
     * Requires kea-ctrl-agent to be enabled (Services -> Kea DHCP -> Control Agent).
     * Returns 0 on success, 1 on failure.
     */
    $script = '/usr/local/opnsense/scripts/keaunbound/reservation-sync.py';

    if (!file_exists($script)) {
        service_log("KeaUnbound: reservation-sync.py not found at $script\n", $verbose);
        keaunbound_log_error("reservation-sync.py not found at $script");
        return 1;
    }

    service_log("KeaUnbound: calling $script...\n", $verbose);
    $ret = mwexecf('%s', [$script]);

    if ($ret !== 0) {
        service_log("KeaUnbound: reservation-sync.py failed with exit code $ret\n", $verbose);
        keaunbound_log_error("reservation-sync.py failed with exit code $ret");
        return 1;
    } else {
        service_log("KeaUnbound: reservation-sync.py completed successfully\n", $verbose);
        return 0;
    }
}

function keaunbound_lease_sync($verbose = false)
{
    /*
     * Sync Kea active leases to Unbound via lease-sync.py.
     * Queries kea-ctrl-agent REST API for all currently active leases
     * and registers each one via unbound-control local_data with TTL
     * matching the lease expiration time.
     *
     * This restores dynamic lease registrations after an Unbound reload
     * or restart, ensuring DNS entries are available without waiting for
     * clients to renew their leases.
     *
     * Requires kea-ctrl-agent to be enabled (Services -> Kea DHCP -> Control Agent).
     * Returns 0 on success, 1 on failure.
     */
    $script = '/usr/local/opnsense/scripts/keaunbound/lease-sync.py';

    if (!file_exists($script)) {
        service_log("KeaUnbound: lease-sync.py not found at $script\n", $verbose);
        keaunbound_log_error("lease-sync.py not found at $script");
        return 1;
    }

    service_log("KeaUnbound: calling $script...\n", $verbose);
    $ret = mwexecf('%s', [$script]);

    if ($ret !== 0) {
        service_log("KeaUnbound: lease-sync.py failed with exit code $ret\n", $verbose);
        keaunbound_log_error("lease-sync.py failed with exit code $ret");
        return 1;
    } else {
        service_log("KeaUnbound: lease-sync.py completed successfully\n", $verbose);
        return 0;
    }
}

function keaunbound_start_do($verbose = false)
{
    /*
     * Start the kea-unbound-ddns.py daemon via configd.
     * Registered on the bootup hook at priority 2, which ensures we start
     * after Unbound (no priority suffix = default/1). Kea does not use the
     * bootup hook so no explicit ordering against it is needed -- our daemon
     * should be ready before Kea's rc.d startup completes.
     *
     * configd_run() is non-blocking — it sends the action and returns
     * immediately without waiting for the daemon to be fully up. This is
     * correct since daemon(8) forks immediately and the action completes.
     */
    $cfg = new \OPNsense\KeaUnbound\General();
    if (empty((string)$cfg->general->enabled)) {
        service_log("KeaUnbound: disabled — skipping daemon start.\n", $verbose);
        return;
    }

    service_log('KeaUnbound: starting daemon...', $verbose);
    configd_run('keaunbound start');
    service_log("done.\n", $verbose);
}

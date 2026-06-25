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
 * keaubnd.inc -- OPNsense plugin hooks for os-kea-ubnd-ddns.
 *
 * The resident daemon (kea-ubnd-ddns.py) owns consistency end-to-end: it
 * watches Kea and Unbound service pidfiles, detects restarts, and drives
 * kea-sync.py to repopulate Unbound. No PHP configure hooks are needed for
 * runtime resync -- the daemon self-heals.
 *
 * Hooks (registered in keaubnd_configure()):
 *
 *   bootup (priority 2) -> keaubnd_start_do()
 *       Start the RFC 2136 stub listener daemon via the 'keaubnd start'
 *       configd action, ordered after Unbound (bootup priority 1). All
 *       subsequent resync after boot is handled by the daemon.
 *
 * Service / schedule / logging hooks:
 *   keaubnd_services() -- register the daemon for service control
 *   keaubnd_cron()     -- declare the auto-clean schedule (OPNsense cron)
 *   keaubnd_syslog()   -- register the 'kea-ubnd' log facility
 */

/**
 * Log a plugin error to syslog under the shared 'kea-ubnd' program tag so PHP
 * error paths land in the keaubnd log alongside the daemon and Python tools.
 */
function keaubnd_log_error($message)
{
    openlog('kea-ubnd', LOG_PID, LOG_DAEMON);
    syslog(LOG_ERR, $message);
    closelog();
}

function keaubnd_syslog()
{
    // Key must be a valid syslog-ng identifier (no hyphens). The template
    // generates filter/destination names like f_local_keaubnd and routes
    // logs to /var/log/keaubnd/keaubnd_YYYYMMDD.log.
    // The facility list is the syslog program tag shared by every component
    // (daemon, Python sync/audit/clean tools, start.py, and PHP error paths).
    // It must avoid the substring "unbound" — the core resolver filter is
    // program("unbound") and matches it as a substring — hence 'kea-ubnd'.
    return ['keaubnd' => ['facility' => [
        'kea-ubnd',
    ]]];
}

function keaubnd_services()
{
    $services = [];

    $cfg = new \OPNsense\KeaUbnd\General();
    if (empty((string)$cfg->general->enabled)) {
        return $services;
    }

    $services[] = [
        'configd' => [
            'restart' => ['keaubnd restart'],
            'start'   => ['keaubnd start'],
            'stop'    => ['keaubnd stop'],
        ],
        'name'        => 'kea-ubnd-ddns',
        'description' => gettext('Kea Unbound DDNS registration'),
        'pidfile'     => '/var/run/kea-ubnd-ddns.pid',
    ];

    return $services;
}

function keaubnd_cron()
{
    /*
     * Register scheduled cron jobs the OPNsense way.
     *
     * plugins_cron() reconciles this return value into the cron model by
     * origin; the Cron template renders it into the managed crontab. When
     * the feature is disabled we return no jobs and the next cron rebuild
     * drops all entries.
     *
     * Two independent job groups:
     *
     * Group 1 — sync/clean (enable_auto_clean):
     *   1a. sync_full  -- full Kea -> Unbound reconcile (cron_run_sync)
     *   1b. clean      -- stale-record purge (cron_run_clean)
     *   Sync runs before clean; both hold the shared advisory mutex (blocking).
     *   Intervals: h1/h3/h6/h12=every N hours, daily=once at auto_clean_hour.
     *
     * Group 2 — fast-reload safety net (enable_fast_reload_cron):
     *   2a. fast_reload -- snapshot all records, unbound-control fast-reload,
     *   restore snapshot (atomic under the mutation lock). No Kea queries;
     *   records are preserved exactly as they were. Runs independently of the
     *   sync/clean schedule. Catches the daemon-restart-without-Unbound-restart
     *   scenario where the in-process mutation counter resets to zero but
     *   Unbound heap keeps growing.
     *   Interval: every N days (d1/d3/d7/d14/d30) at 03:00.
     */
    $jobs = [];

    $cfg = new \OPNsense\KeaUbnd\General();
    if (empty((string)$cfg->general->enabled)) {
        return $jobs;
    }

    // ── Group 1: sync / clean ──────────────────────────────────────────────
    if (!empty((string)$cfg->general->enable_auto_clean)) {
        $run_sync  = !empty((string)$cfg->general->cron_run_sync);
        $run_clean = !empty((string)$cfg->general->cron_run_clean);

        if ($run_sync || $run_clean) {
            $interval = (string)$cfg->general->auto_clean_interval;

            if ($interval === 'daily') {
                $hour = (string)$cfg->general->auto_clean_hour;
                if (!ctype_digit($hour) || (int)$hour < 0 || (int)$hour > 23) {
                    $hour = '0';
                }
                $minute = '0';
            } else {
                $hour_by_interval = [
                    'h1'  => '*',
                    'h3'  => '0,3,6,9,12,15,18,21',
                    'h6'  => '0,6,12,18',
                    'h12' => '0,12',
                ];
                $hour   = $hour_by_interval[$interval] ?? '0,6,12,18';
                $minute = '0';
            }

            if ($run_sync) {
                $jobs[]['autocron'] = [
                    '/usr/local/sbin/configctl -d keaubnd sync_full',
                    $minute,
                    $hour,
                ];
            }
            if ($run_clean) {
                $jobs[]['autocron'] = [
                    '/usr/local/sbin/configctl -d keaubnd clean',
                    $minute,
                    $hour,
                ];
            }
        }
    }

    // ── Group 2: fast-reload safety net ───────────────────────────────────
    if (!empty((string)$cfg->general->enable_fast_reload_cron)) {
        // Map d1/d3/d7/d14/d30 to a day-of-month step for standard cron.
        // */N fires on days 1,1+N,1+2N,... of the month — close enough for
        // a maintenance window that runs regardless of traffic volume.
        $day_map = ['d1' => '1', 'd3' => '3', 'd7' => '7', 'd14' => '14', 'd30' => '30'];
        $days_key = (string)$cfg->general->fast_reload_cron_days;
        $day_step = $day_map[$days_key] ?? '7';
        $day_field = ($day_step === '1') ? '*' : '*/' . $day_step;
        $cron_hour = (string)$cfg->general->fast_reload_cron_hour;
        $cron_hour = (is_numeric($cron_hour) && $cron_hour >= 0 && $cron_hour <= 23) ? $cron_hour : '3';

        $jobs[]['autocron'] = [
            '/usr/local/sbin/configctl -d keaubnd fast_reload',
            '0',        // minute
            $cron_hour, // hour
            $day_field, // day-of-month
        ];
    }

    return $jobs;
}

function keaubnd_configure()
{
    return [
        'bootup' => ['keaubnd_start_do:2'],
    ];
}

function keaubnd_start_do($verbose = false)
{
    /*
     * Start the kea-ubnd-ddns.py daemon via configd.
     * Registered on the bootup hook at priority 2, which ensures we start
     * after Unbound (no priority suffix = default/1). Kea does not use the
     * bootup hook so no explicit ordering against it is needed -- our daemon
     * should be ready before Kea's rc.d startup completes.
     *
     * configd_run() is non-blocking — it sends the action and returns
     * immediately without waiting for the daemon to be fully up. This is
     * correct since daemon(8) forks immediately and the action completes.
     */
    $cfg = new \OPNsense\KeaUbnd\General();
    if (empty((string)$cfg->general->enabled)) {
        service_log("KeaUbnd: disabled — skipping daemon start.\n", $verbose);
        return;
    }

    service_log('KeaUbnd: starting daemon...', $verbose);
    configd_run('keaubnd start');
    service_log("done.\n", $verbose);
}

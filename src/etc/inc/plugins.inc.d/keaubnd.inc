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
     *
     * Intervals: h1=every hour, h3=every 3h, h6=every 6h, h12=every 12h,
     * daily=once per day at auto_clean_hour (0-23).
     */
    $jobs = [];

    $cfg = new \OPNsense\KeaUbnd\General();
    if (!empty((string)$cfg->general->enabled) && !empty((string)$cfg->general->enable_auto_clean)) {
        $interval = (string)$cfg->general->auto_clean_interval;

        if ($interval === 'daily') {
            $hour = (string)$cfg->general->auto_clean_hour;
            if (!ctype_digit($hour) || (int)$hour < 0 || (int)$hour > 23) {
                $hour = '0';
            }
            $jobs[]['autocron'] = [
                '/usr/local/sbin/configctl -d keaubnd clean',
                '0',
                $hour,
            ];
        } else {
            $hour_by_interval = [
                'h1'  => '*',
                'h3'  => '0,3,6,9,12,15,18,21',
                'h6'  => '0,6,12,18',
                'h12' => '0,12',
            ];
            $hour = $hour_by_interval[$interval] ?? '0,6,12,18';
            $jobs[]['autocron'] = [
                '/usr/local/sbin/configctl -d keaubnd clean',
                '0',
                $hour,
            ];
        }
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

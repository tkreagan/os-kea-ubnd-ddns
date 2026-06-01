<?php

/*
 * Copyright (C) 2026 tkr
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
 * keaunbound.inc -- OPNsense plugin hooks for os-kea-unbound
 *
 * Hook registrations:
 *
 *   kea_sync (priority 2) -- fires after Kea rewrites its config and restarts.
 *
 *     Step 1 (always): call unbound_add_host_entries() to rewrite
 *     host_entries.conf. This fixes a core OPNsense limitation: normally
 *     host_entries.conf is only rewritten when Unbound reconfigures, not
 *     when Kea config changes. Without this, our is_static_entry() guard
 *     in kea-unbound-ddns.py can over-protect -- blocking DELETE updates
 *     for reservations removed from Kea because the stale host_entries.conf
 *     still lists them.
 *
 *     if regdhcpstatic is enabled (Services -> Unbound DNS -> General ->
 *     Register DHCP Static Mappings):
 *       Step 2: reload Unbound so updated static reservations become
 *               visible in DNS. This wipes all runtime local_data entries
 *               injected by kea-unbound-ddns.py for dynamic leases.
 *       Step 3: lease DB sync to restore dynamic lease registrations
 *               lost during the Unbound reload.
 *
 *     if regdhcpstatic is disabled (our plugin manages all DHCP DNS):
 *       Step 2: reservation sync -- read static reservations directly from
 *               Kea config and register them in Unbound immediately. This
 *               ensures a newly added reservation (e.g. foo.bar.com ->
 *               10.10.10.10) appears in DNS right away, before the device
 *               has connected and received its lease.
 *       No lease sync needed -- we did not reload Unbound, so dynamic
 *       local_data from kea-unbound-ddns.py remains intact.
 *
 *   unbound_start -- fires when Unbound starts or restarts (boot, manual
 *     reload, or after the regdhcpstatic reload above).
 *       Step 1: reservation sync -- register all static reservations
 *       Step 2: lease DB sync -- register all active dynamic leases
 *     Together these fully repopulate Unbound from scratch without waiting
 *     for devices to renew their leases.
 *
 *   bootup (priority 2) -- ensures our daemon starts after Unbound (priority
 *     1, no suffix = default). Kea does not register on the bootup hook --
 *     it starts via kea_services() which is handled by OPNsense's service
 *     manager after the bootup hook chain completes. Our daemon is therefore
 *     always ready before Kea starts sending DNS UPDATE packets.
 *
 * Verified: Unbound uses bootup with no priority (default=1). Kea does not
 *   use the bootup hook. Our :2 priority correctly places us after Unbound.
 * TODO: implement keaunbound_reservation_sync() -- reads Kea config via
 *       kea-ctrl-agent API and registers static reservations in Unbound.
 * TODO: implement keaunbound_lease_sync() -- queries kea-ctrl-agent REST API
 *       for all active leases and registers them via unbound-control local_data.
 * TODO: implement keaunbound_start_do() -- start daemon via configd.
 * TODO: implement keaunbound_services() -- register with OPNsense service manager.
 * TODO: implement keaunbound_syslog() -- register log facility.
 * TODO: implement MVC model, controller, and UI view.
 * TODO: implement stale record audit in the sync script (kea-unbound-sync.py).
 *       local_data entries injected via unbound-control never expire -- if
 *       kea-dhcp-ddns crashes after an add but before the corresponding delete,
 *       stale A/AAAA/PTR records can accumulate indefinitely. The audit should:
 *         1. Dump list_local_data
 *         2. Cross-reference each A/AAAA record against:
 *              - host_entries.conf (OPNsense-owned, expected)
 *              - Kea active leases via ctrl-agent API (our records, expected)
 *              - Kea static reservations via ctrl-agent API (our records, expected)
 *         3. Flag any record not found in any of the above as potentially stale
 *         4. Report flagged records (hostname, IP, type) for human review
 *         5. PTR records should be treated as paired with their forward record --
 *            report both together when a forward record is flagged
 *         6. Optional --clean flag to remove flagged records after confirmation
 *       The audit should never silently delete -- we do not own all of local_data
 *       and other tools may be writing there. Conservative reporting only unless
 *       --clean is explicitly passed.
 *       Natural fit as an audit mode in kea-unbound-sync.py alongside the normal
 *       sync mode. Could be scheduled weekly via OPNsense cron or scheduled tasks.
 */

function keaunbound_syslog()
{
    return ['kea-unbound-ddns' => ['facility' => [
        'kea-unbound-ddns',
    ]]];
}

function keaunbound_services()
{
    $services = [];

    $cfg = new \OPNsense\KeaUnbound\General();
    if (empty((string)$cfg->enabled)) {
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

function keaunbound_configure()
{
    return [
        'kea_sync'      => ['keaunbound_on_kea_sync:2'],
        'unbound_start' => ['keaunbound_on_unbound_start'],
        'bootup'        => ['keaunbound_start_do:2'],
    ];
}

function keaunbound_on_kea_sync($verbose = false)
{
    /*
     * Step 1 (always): rewrite host_entries.conf so our is_static_entry()
     * guard has current data. See hook registration comment for details.
     */
    if (function_exists('unbound_add_host_entries')) {
        service_log('KeaUnbound: refreshing host_entries.conf...', $verbose);
        unbound_add_host_entries();
        service_log("done.\n", $verbose);
    } else {
        service_log("KeaUnbound: unbound_add_host_entries() not available -- skipping.\n", $verbose);
    }

    $cfg = new \OPNsense\KeaUnbound\General();
    $reload_on_sync = !empty((string)$cfg->general->reload_unbound_on_kea_sync);

    if ($reload_on_sync) {
        /*
         * regdhcpstatic is on -- OPNsense manages static reservation DNS.
         * Step 2: reload Unbound to pick up updated static reservations.
         *         This wipes all runtime local_data entries for dynamic leases.
         * Step 3: resync dynamic leases to restore what the reload wiped.
         */
        service_log('KeaUnbound: regdhcpstatic enabled -- reloading Unbound...', $verbose);
        unbound_configure_do($verbose);
        service_log("done.\n", $verbose);

        service_log('KeaUnbound: resyncing dynamic leases after reload...', $verbose);
        keaunbound_lease_sync($verbose);
        service_log("done.\n", $verbose);
    } else {
        /*
         * regdhcpstatic is off -- our plugin manages all DHCP DNS.
         * Step 2: reservation sync to register static reservations immediately
         *         (e.g. foo.bar.com -> 10.10.10.10 appears in DNS now, before
         *         the device has connected and received its lease).
         * No lease sync needed -- dynamic local_data is intact since we did
         * not reload Unbound.
         */
        service_log('KeaUnbound: syncing static reservations...', $verbose);
        keaunbound_reservation_sync($verbose);
        service_log("done.\n", $verbose);
    }
}

function keaunbound_on_unbound_start($verbose = false)
{
    /*
     * Unbound just started (boot, manual reload, or post-regdhcpstatic reload).
     * local_data is empty -- fully repopulate from Kea without waiting for
     * lease renewals.
     *
     * Step 1: register all static reservations from Kea config.
     * Step 2: register all active dynamic leases from Kea lease DB.
     */
    service_log('KeaUnbound: syncing reservations on Unbound start...', $verbose);
    keaunbound_reservation_sync($verbose);
    service_log("done.\n", $verbose);

    service_log('KeaUnbound: syncing active leases on Unbound start...', $verbose);
    keaunbound_lease_sync($verbose);
    service_log("done.\n", $verbose);
}

function keaunbound_reservation_sync($verbose = false)
{
    /*
     * TODO: Read static reservations from Kea config via kea-ctrl-agent
     * REST API and register each one in Unbound via unbound-control local_data.
     * This ensures reservations appear in DNS immediately when added to Kea,
     * regardless of whether the device has connected and received a lease.
     *
     * Must respect is_static_entry() guard -- skip any reservation whose
     * hostname already appears in host_entries.conf (i.e. regdhcpstatic is
     * on and OPNsense has already registered it).
     *
     * Requires kea-ctrl-agent to be enabled (Services -> Kea DHCP ->
     * Control Agent).
     */
    service_log("KeaUnbound: reservation sync not yet implemented.\n", $verbose);
}

function keaunbound_lease_sync($verbose = false)
{
    /*
     * TODO: Query kea-ctrl-agent REST API for all currently active leases
     * and register each one via unbound-control local_data. This restores
     * dynamic lease registrations after an Unbound reload or restart.
     *
     * Requires kea-ctrl-agent to be enabled (Services -> Kea DHCP ->
     * Control Agent).
     */
    service_log("KeaUnbound: lease sync not yet implemented.\n", $verbose);
}

function keaunbound_start_do($verbose = false)
{
    /*
     * Start the kea-unbound-ddns.py daemon via configd.
     * Registered on the bootup hook at priority 2, which ensures we start
     * after Unbound (no priority suffix = default/1). Kea does not use the
     * bootup hook so no explicit ordering against it is needed -- our daemon
     * will be ready before Kea's rc.d startup completes.
     *
     * configd_run() is non-blocking — it sends the action and returns
     * immediately without waiting for the daemon to be fully up. This is
     * correct since daemon(8) forks immediately and the action completes.
     */
    $cfg = new \OPNsense\KeaUnbound\General();
    if (empty((string)$cfg->enabled)) {
        service_log("KeaUnbound: disabled — skipping daemon start.\n", $verbose);
        return;
    }

    service_log('KeaUnbound: starting daemon...', $verbose);
    configd_run('keaunbound start');
    service_log("done.\n", $verbose);
}

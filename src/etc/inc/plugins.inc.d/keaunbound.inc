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
 * keaunbound.inc — OPNsense plugin hooks for os-kea-unbound
 *
 * Hook registrations:
 *
 *   kea_sync (priority 2) — fires after Kea rewrites its config and restarts.
 *     We call unbound_add_host_entries() to rewrite host_entries.conf with
 *     the current Kea reservations. This fixes a core OPNsense limitation:
 *     host_entries.conf is normally only rewritten when Unbound reconfigures,
 *     not when Kea config changes. Without this, our is_static_entry() guard
 *     in kea-unbound-ddns.py can over-protect — blocking DELETE updates for
 *     reservations that no longer exist in Kea because the stale
 *     host_entries.conf still lists them.
 *
 *     If regdhcpstatic is enabled in Unbound (Services → Unbound DNS →
 *     General → Register DHCP Static Mappings), we also need to reload
 *     Unbound so the updated static reservations become visible in DNS.
 *     However, reloading Unbound wipes all runtime local_data entries that
 *     kea-unbound-ddns.py injected for dynamic leases. We therefore trigger
 *     a lease DB sync after the reload to restore dynamic lease registrations
 *     from the Kea control agent REST API.
 *
 *     Sequence when regdhcpstatic is enabled:
 *       1. unbound_add_host_entries() — rewrite host_entries.conf
 *       2. unbound_configure_do()     — reload Unbound (wipes local_data)
 *       3. keaunbound_lease_sync()    — restore dynamic leases from Kea DB
 *
 *     Sequence when regdhcpstatic is disabled:
 *       1. unbound_add_host_entries() — rewrite host_entries.conf only
 *       (no Unbound reload needed — dynamic local_data stays intact)
 *
 *   unbound_start — fires when Unbound starts or restarts (boot, manual
 *     reload, or post-regdhcpstatic reload above). Runs keaunbound_lease_sync()
 *     to populate Unbound with all currently active Kea leases. Without this,
 *     DNS is incomplete until each device renews its lease.
 *
 *   bootup (priority 2) — ensures our daemon starts after Unbound (1) but
 *     before Kea (3), so the stub is ready to receive DNS UPDATE packets
 *     when Kea replays its lease database on startup.
 *
 * TODO: verify Unbound and Kea bootup priorities to confirm :2 is correct.
 * TODO: implement keaunbound_lease_sync() — queries kea-ctrl-agent REST API
 *       for all active leases and registers them via unbound-control local_data.
 * TODO: implement keaunbound_services() — register daemon with OPNsense
 *       service manager so it appears in the Services status page.
 * TODO: implement keaunbound_syslog() — register log facility.
 * TODO: implement MVC model, controller, and UI view.
 */

function keaunbound_configure()
{
    return [
        'kea_sync'      => ['keaunbound_on_kea_sync:2'],
        'unbound_start' => ['keaunbound_lease_sync'],
        'bootup'        => ['keaunbound_start_do:2'],
    ];
}

function keaunbound_on_kea_sync($verbose = false)
{
    /*
     * Step 1: Always rewrite host_entries.conf so our is_static_entry()
     * guard has current data. This fixes the stale host_entries.conf
     * problem — see hook registration comment above for details.
     */
    if (function_exists('unbound_add_host_entries')) {
        service_log('KeaUnbound: refreshing host_entries.conf...', $verbose);
        unbound_add_host_entries();
        service_log("done.\n", $verbose);
    } else {
        service_log("KeaUnbound: unbound_add_host_entries() not available — skipping.\n", $verbose);
    }

    /*
     * Step 2: If regdhcpstatic is enabled, reload Unbound so updated static
     * reservations are visible in DNS, then resync dynamic leases to restore
     * what the reload wiped from runtime local_data.
     *
     * If regdhcpstatic is disabled, skip the reload — dynamic local_data
     * entries from kea-unbound-ddns.py remain intact.
     */
    $unbound = new \OPNsense\Unbound\Unbound();
    $regdhcpstatic = !empty((string)$unbound->general->regdhcpstatic);

    if ($regdhcpstatic) {
        service_log('KeaUnbound: regdhcpstatic enabled — reloading Unbound...', $verbose);
        unbound_configure_do($verbose);
        service_log("done.\n", $verbose);

        /*
         * Step 3: Restore dynamic lease registrations lost during Unbound
         * reload. TODO: implement keaunbound_lease_sync().
         */
        service_log('KeaUnbound: resyncing dynamic leases...', $verbose);
        keaunbound_lease_sync($verbose);
        service_log("done.\n", $verbose);
    }
}

function keaunbound_lease_sync($verbose = false)
{
    /*
     * TODO: Query the Kea control agent REST API (kea-ctrl-agent on
     * 127.0.0.1:8000) for all currently active leases, then register
     * each one via unbound-control local_data. This repopulates Unbound
     * after a restart or reload without waiting for lease renewals.
     *
     * Requires kea-ctrl-agent to be enabled (Services → Kea DHCP →
     * Control Agent).
     *
     * This function is called from two hooks:
     *   - unbound_start: Unbound just started, local_data is empty
     *   - keaunbound_on_kea_sync: Unbound was reloaded due to regdhcpstatic,
     *     local_data was wiped and needs to be restored
     */
    service_log("KeaUnbound: lease sync not yet implemented.\n", $verbose);
}

function keaunbound_start_do($verbose = false)
{
    /*
     * TODO: Start the kea-unbound-ddns.py daemon via configd.
     * Must run after Unbound (priority 1) and before Kea (priority 3)
     * so the stub is ready when Kea replays leases on startup.
     */
    service_log("KeaUnbound: daemon start not yet implemented.\n", $verbose);
}

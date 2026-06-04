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

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\KeaUnbound\General';

    /**
     * Retrieve current settings.
     * GET /api/keaunbound/general/get
     */
    public function getAction()
    {
        return parent::getAction();
    }

    /**
     * Save settings.
     * POST /api/keaunbound/general/set
     *
     * Just saves the config. Use reconfigure to apply changes.
     */
    public function setAction()
    {
        return parent::setAction();
    }

    /**
     * Apply settings — intelligently restart daemon if needed and update cron.
     * Detects if TSIG/port settings changed and only restarts if necessary.
     * Always updates cron job configuration.
     * POST /api/keaunbound/general/reconfigure
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();

            // Always restart the daemon (v1): port/TSIG/enable settings are baked
            // into the daemon's launch args by start.py and only read at startup,
            // so any apply requires a restart to take effect. This also handles the
            // enable/disable transition (start.py is enable-aware, restart pkills first).
            $backend->configdRun('keaunbound restart');

            // Rebuild cron (core action) so the keaunbound_cron() job is
            // (re)materialized or removed to match the current auto-clean settings.
            $backend->configdRun('cron restart');

            return ['status' => 'ok'];
        }
        return ['status' => 'error'];
    }

    /**
     * Immediately sync Kea static reservations to Unbound.
     * POST /api/keaunbound/general/sync_static
     */
    public function syncStaticAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('keaunbound sync_static');

            return ['status' => 'ok', 'message' => 'Static reservations sync triggered'];
        }
        return ['status' => 'error'];
    }

    /**
     * Immediately sync Kea active leases to Unbound.
     * POST /api/keaunbound/general/sync_dynamic
     */
    public function syncDynamicAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('keaunbound sync_dynamic');

            return ['status' => 'ok', 'message' => 'Dynamic leases sync triggered'];
        }
        return ['status' => 'error'];
    }

    /**
     * Immediately clean stale DNS records from Unbound.
     * POST /api/keaunbound/general/clean
     */
    public function cleanAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('keaunbound clean');

            return ['status' => 'ok', 'message' => 'Cleanup triggered'];
        }
        return ['status' => 'error'];
    }
}

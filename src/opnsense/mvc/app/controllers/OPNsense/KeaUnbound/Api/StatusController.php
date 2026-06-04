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

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class StatusController extends ApiControllerBase
{
    /**
     * Get comprehensive DNS registration status across all sources.
     * Calls local-data-audit.py to audit Unbound local_data against Kea
     * reservations, Kea leases, and host_entries.conf.
     *
     * Returns JSON with structure:
     * {
     *   "complete": bool,
     *   "kea_error": string | null,
     *   "records": [
     *     {
     *       "hostname": string,
     *       "ip": string,
     *       "type": "A" | "AAAA",
     *       "ptr_registered": bool,
     *       "source": "reservation" | "lease" | "unbound_local_data" | "static",
     *       "in_unbound": bool,
     *       "status": "ok" | "missing-PTR" | "stale" | "orphaned-PTR" | "static"
     *     }
     *   ],
     *   "orphaned_ptrs": [
     *     {
     *       "ptr_name": string,
     *       "data": string,
     *       "status": "orphaned-PTR"
     *     }
     *   ]
     * }
     *
     * GET /api/keaunbound/status/audit
     */
    public function auditAction()
    {
        $script = '/usr/local/opnsense/scripts/keaunbound/local-data-audit.py';

        // Check if script exists
        if (!file_exists($script)) {
            return [
                'status' => 'error',
                'message' => 'Status audit script not found',
                'complete' => false,
                'kea_error' => 'audit script unavailable'
            ];
        }

        // Run the audit script with JSON output. $script is a fixed constant
        // path with no user input, so no shell-argument escaping is needed.
        $output = [];
        $returnCode = 0;

        exec($script . ' --report-json 2>&1', $output, $returnCode);

        // Join output lines
        $jsonOutput = implode("\n", $output);

        // Try to parse JSON
        $result = json_decode($jsonOutput, true);

        if ($result === null) {
            // JSON parse failed - script may have errored. Tag under the shared
            // 'kea-ub' program name so these land in the keaunbound log.
            \openlog('kea-ub', LOG_PID, LOG_DAEMON);
            \syslog(LOG_ERR, "audit script failed or returned invalid JSON");
            \syslog(LOG_ERR, "output was: " . $jsonOutput);
            \closelog();

            return [
                'status' => 'error',
                'message' => 'Audit script failed',
                'complete' => false,
                'kea_error' => 'audit execution failed'
            ];
        }

        // Script succeeded and returned valid JSON
        return [
            'status' => 'ok',
            'audit' => $result
        ];
    }
}

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

namespace OPNsense\KeaUbnd\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\KeaUbnd\General';
    protected static $internalServiceTemplate = null;
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'keaubnd';

    /**
     * Readiness/consistency status of the resident daemon, read from the status
     * file the daemon and start.py write (/var/run/keaubnd/daemon-status).
     * One tab-separated line: "<state>\t<detail>\t<epoch>".
     *
     * States: running | blocked | starting | refused | stopped | alert | unknown.
     * The UI banner uses this to explain a not-running daemon (refused/stopped)
     * or a transient repopulation (blocked), beyond the plain service up/down.
     */
    public function readinessAction()
    {
        $file = '/var/run/keaubnd/daemon-status';
        $result = ['state' => 'unknown', 'detail' => '', 'age' => null];
        if (is_readable($file)) {
            $line = trim(@file_get_contents($file));
            if ($line !== '') {
                $parts = explode("\t", $line);
                $result['state'] = $parts[0] ?? 'unknown';
                $result['detail'] = $parts[1] ?? '';
                if (isset($parts[2]) && is_numeric($parts[2])) {
                    $result['age'] = time() - (int)$parts[2];
                }
            }
        }
        return $result;
    }
}

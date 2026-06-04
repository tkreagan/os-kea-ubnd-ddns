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

namespace OPNsense\KeaUnbound;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class General extends BaseModel
{
    /**
     * When TSIG authentication is enabled, the key name and a base64 secret are
     * mandatory. Blocking the save here (fail closed) keeps the saved config and
     * the daemon in agreement — start.py refuses to launch the listener if TSIG
     * is enabled without a usable key.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        if ((string)$this->general->enable_tsig == '1') {
            if (trim((string)$this->general->tsig_key_name) == '') {
                $messages->appendMessage(new Message(
                    gettext('A TSIG key name is required when TSIG authentication is enabled.'),
                    $this->general->tsig_key_name->__reference()
                ));
            }

            $secret = trim((string)$this->general->tsig_key_secret);
            if ($secret === '') {
                $messages->appendMessage(new Message(
                    gettext('A TSIG key secret is required when TSIG authentication is enabled.'),
                    $this->general->tsig_key_secret->__reference()
                ));
            } elseif (base64_decode($secret, true) === false) {
                $messages->appendMessage(new Message(
                    gettext('The TSIG key secret must be base64-encoded.'),
                    $this->general->tsig_key_secret->__reference()
                ));
            }
        }

        return $messages;
    }
}

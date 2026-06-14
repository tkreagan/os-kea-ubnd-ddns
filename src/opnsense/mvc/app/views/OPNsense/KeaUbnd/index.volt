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

<script>
    // Resident-daemon readiness banner. Reads the status file the daemon and
    // start.py write, so the UI can explain a not-running daemon (refused /
    // stopped) or a transient repopulation (blocked) beyond plain up/down.
    function updateReadiness() {
        ajaxGet('/api/keaubnd/service/readiness', {}, function(data, status) {
            if (status !== 'success' || !data) { return; }
            const banners = {
                refused: ['danger', 'fa-circle-xmark',
                          '{{ lang._('DDNS listener not started') }}'],
                stopped: ['danger', 'fa-circle-xmark',
                          '{{ lang._('DDNS listener stopped') }}'],
                alert:   ['warning', 'fa-triangle-exclamation',
                          '{{ lang._('DDNS listener degraded') }}'],
                blocked: ['warning', 'fa-circle-nodes',
                          '{{ lang._('Repopulating DNS after a Kea/Unbound restart') }}'],
            };
            const b = banners[data.state];
            const $box = $('#keaubnd_readiness');
            if (!b) { $box.hide().empty(); return; }
            const detail = data.detail ? (' — ' + $('<div>').text(data.detail).html()) : '';
            $box.html('<div class="alert alert-' + b[0] + '" role="alert">'
                + '<i class="fa-solid ' + b[1] + '"></i> <b>' + b[2] + '</b>' + detail
                + '</div>').show();
        });
    }

    function updateCleanScheduleUI() {
        var isDaily = $('select[id="general.general.auto_clean_interval"]').val() === 'daily';
        $('tr[id="row_general.general.auto_clean_hour"]').toggle(isDaily);
    }

    $( document ).ready(function() {
        let data_get_map = {'frm_generalsettings': "/api/keaubnd/general/get"};
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('keaubnd');
            updateCleanScheduleUI();
        });

        $('select[id="general.general.auto_clean_interval"]').change(updateCleanScheduleUI);

        updateReadiness();
        setInterval(updateReadiness, 5000);

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint(
                    "/api/keaubnd/general/set",
                    'frm_generalsettings',
                    function() { dfObj.resolve(); },
                    true,
                    function() { dfObj.reject(); }
                );
                return dfObj;
            }
        });
        // The manual Sync and Clean action buttons now live together on the
        // Lease Audit tab, next to the records they affect.
    });
</script>

<div id="keaubnd_readiness" style="display:none; margin-bottom:10px;"></div>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': formGeneralSettings, 'id': 'frm_generalsettings']) }}
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/keaubnd/general/reconfigure', 'data_service_widget': 'keaubnd'}) }}

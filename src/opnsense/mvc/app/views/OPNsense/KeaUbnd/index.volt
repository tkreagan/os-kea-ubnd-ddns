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

    var _logwatchSubopts = [
        'general.general.logwatch_on_release',
        'general.general.logwatch_on_servfail',
        'general.general.logwatch_on_missed_remove',
    ];
    var _cronSubopts = [
        'general.general.cron_run_sync',
        'general.general.cron_run_clean',
        'general.general.auto_clean_interval',
        'general.general.auto_clean_hour',
    ];
    var _magicSubopts = [
        'general.general.write_magic_ptrs',
        'general.general.magic_laa_tag',
    ];

    function indentSubopts() {
        $.each(_logwatchSubopts.concat(_cronSubopts).concat(_magicSubopts), function(_, id) {
            $('tr[id="row_' + id + '"] td:first-child').css('padding-left', '2.5em');
        });
    }

    function updateMagicSuboptsUI() {
        var magicOn = $('input[id="general.general.magic_names"]').prop('checked');
        var synthOn = $('input[id="general.general.synthesize_ptr"]').prop('checked');
        var ptrEnabled = magicOn && synthOn;
        $('input[id="general.general.write_magic_ptrs"]').prop('disabled', !ptrEnabled);
        $('tr[id="row_general.general.write_magic_ptrs"]').toggleClass('text-muted', !ptrEnabled);
        $('input[id="general.general.magic_laa_tag"]').prop('disabled', !magicOn);
        $('tr[id="row_general.general.magic_laa_tag"]').toggleClass('text-muted', !magicOn);
    }

    function updateLogwatchSuboptsUI() {
        var on = $('input[id="general.general.enable_logwatch"]').prop('checked');
        $('tr[id="row_general.general.logwatch_on_release"]').toggle(on);
        $('tr[id="row_general.general.logwatch_on_servfail"]').toggle(on);
        $('tr[id="row_general.general.logwatch_on_missed_remove"]').toggle(on);
    }

    function updateCronSuboptsUI() {
        var on = $('input[id="general.general.enable_auto_clean"]').prop('checked');
        $('tr[id="row_general.general.cron_run_sync"]').toggle(on);
        $('tr[id="row_general.general.cron_run_clean"]').toggle(on);
        $('tr[id="row_general.general.auto_clean_interval"]').toggle(on);
        $('tr[id="row_general.general.auto_clean_hour"]').toggle(on && $('select[id="general.general.auto_clean_interval"]').val() === 'daily');
    }

    $( document ).ready(function() {
        let data_get_map = {'frm_generalsettings': "/api/keaubnd/general/get"};
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('keaubnd');
            indentSubopts();
            updateLogwatchSuboptsUI();
            updateCronSuboptsUI();
            updateMagicSuboptsUI();
        });

        $('input[id="general.general.enable_logwatch"]').change(updateLogwatchSuboptsUI);
        $('input[id="general.general.enable_auto_clean"]').change(updateCronSuboptsUI);
        $('select[id="general.general.auto_clean_interval"]').change(updateCronSuboptsUI);
        $('input[id="general.general.magic_names"]').change(updateMagicSuboptsUI);
        $('input[id="general.general.synthesize_ptr"]').change(updateMagicSuboptsUI);

        updateReadiness();
        setInterval(updateReadiness, 5000);

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();

                var logwatchOn = $('input[id="general.general.enable_logwatch"]').prop('checked');
                if (logwatchOn) {
                    var lwAny = $('input[id="general.general.logwatch_on_release"]').prop('checked')
                             || $('input[id="general.general.logwatch_on_servfail"]').prop('checked')
                             || $('input[id="general.general.logwatch_on_missed_remove"]').prop('checked');
                    if (!lwAny) {
                        alert('{{ lang._("Log Watcher is enabled but no actions are selected. Enable at least one sub-option or disable Log Watcher.") }}');
                        dfObj.reject();
                        return dfObj;
                    }
                }

                var cronOn = $('input[id="general.general.enable_auto_clean"]').prop('checked');
                if (cronOn) {
                    var cronAny = $('input[id="general.general.cron_run_sync"]').prop('checked')
                               || $('input[id="general.general.cron_run_clean"]').prop('checked');
                    if (!cronAny) {
                        alert('{{ lang._("Scheduled sync / clean is enabled but no jobs are selected. Enable at least one sub-option or disable the schedule.") }}');
                        dfObj.reject();
                        return dfObj;
                    }
                }

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

{#
 # Copyright (c) 2026 tkr
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
    $( document ).ready(function() {
        let data_get_map = {'frm_generalsettings': "/api/keaunbound/general/get"};
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('keaunbound');
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint(
                    "/api/keaunbound/general/set",
                    'frm_generalsettings',
                    function() { dfObj.resolve(); },
                    true,
                    function() { dfObj.reject(); }
                );
                return dfObj;
            }
        });

        // Manual sync buttons. (The "Clean stale records" action lives on the
        // Lease Audit tab, next to the records it acts on.)
        function triggerSync(btnId, endpoint) {
            const btn = $("#" + btnId);
            btn.prop("disabled", true);
            ajaxCall(endpoint, {}, function() {
                btn.prop("disabled", false);
            });
        }
        $("#sync_static_now").click(function() {
            triggerSync("sync_static_now", "/api/keaunbound/general/sync_static");
        });
        $("#sync_dynamic_now").click(function() {
            triggerSync("sync_dynamic_now", "/api/keaunbound/general/sync_dynamic");
        });
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': formGeneralSettings, 'id': 'frm_generalsettings']) }}
</div>

<div class="content-box" style="padding: 10px 20px;">
    <button id="sync_static_now" class="btn btn-default" type="button">
        <i class="fa fa-refresh"></i> {{ lang._('Sync Static Reservations Now') }}
    </button>
    <button id="sync_dynamic_now" class="btn btn-default" type="button" style="margin-left: 8px;">
        <i class="fa fa-refresh"></i> {{ lang._('Sync Dynamic Leases Now') }}
    </button>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/keaunbound/general/reconfigure', 'data_service_widget': 'keaunbound'}) }}

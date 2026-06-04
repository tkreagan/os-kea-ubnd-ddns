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
    $( document ).ready(function() {
        let data_get_map = {'frm_generalsettings': "/api/keaunbound/general/get"};
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('keaunbound');

            // The Kea Connection settings are reserved for a future release —
            // show them disabled (grayed out) until the manual-override path is
            // wired in. Purely cosmetic; guarded so it can never break the form.
            try {
                var $conn = $("[id^='general.connection.']");
                $conn.prop('disabled', true);
                $conn.filter('select').selectpicker('refresh');
                $("tr[id^='row_general.connection.']").css('opacity', '0.6');
            } catch (e) { /* non-critical */ }

            // TSIG is not yet tested — grey out its inputs (kept under Advanced
            // for reference). Disabled inputs are still read by saveFormToEndpoint,
            // so stored values are preserved on Apply.
            try {
                ['enable_tsig', 'tsig_key_name', 'tsig_key_secret', 'tsig_algorithm'].forEach(function(f) {
                    var $el = $("[id='general.general." + f + "']");
                    $el.prop('disabled', true);
                    $el.filter('select').selectpicker('refresh');
                    $("tr[id='row_general.general." + f + "']").css('opacity', '0.6');
                });
            } catch (e) { /* non-critical */ }
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
        // The manual Sync and Clean action buttons now live together on the
        // Lease Audit tab, next to the records they affect.
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': formGeneralSettings, 'id': 'frm_generalsettings']) }}
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/keaunbound/general/reconfigure', 'data_service_widget': 'keaunbound'}) }}

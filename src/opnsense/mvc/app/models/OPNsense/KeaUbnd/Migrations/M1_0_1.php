<?php

/**
 * Migration M1_0_1: schema 1.0.0 (package 0.9) → 1.0.1 (package 0.98)
 *
 * - clean_stale_records is new (there was no clean_on_restart in the published
 *   1.0.0 schema — that name existed only in pre-release builds). Set to "1"
 *   for all upgrades; model default also "1" for fresh installs.
 * - magic_names, magic_laa_tag, write_magic_ptrs, logwatch_on_release,
 *   logwatch_on_servfail, logwatch_on_missed_remove, cron_run_sync,
 *   cron_run_clean, enable_fast_reload, fast_reload_threshold,
 *   enable_fast_reload_cron, fast_reload_cron_days, fast_reload_cron_hour
 *   are new fields — model defaults take effect when the model is saved.
 * - sync_static_reservations, sync_dynamic_leases, dirty_set_cap
 *   are removed fields — left as harmless orphan XML (silently ignored on load).
 */

namespace OPNsense\KeaUbnd\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

class M1_0_1 extends BaseModelMigration
{
    public function run($model)
    {
        $config = Config::getInstance()->object();
        $general = $config->OPNsense->KeaUbnd->general ?? null;
        if ($general === null) {
            return;
        }

        // clean_stale_records is new in 1.0.1; was not present in the published 1.0.0 schema.
        if (!isset($general->clean_stale_records) || (string)$general->clean_stale_records === '') {
            $general->addChild('clean_stale_records', '1');
        }
    }
}

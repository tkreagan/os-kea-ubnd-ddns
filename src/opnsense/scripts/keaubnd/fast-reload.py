#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
fast-reload.py -- Reclaim Unbound heap memory fragmented by repeated local_data
mutations, restoring all records atomically.

Under the advisory mutation lock:
  1. list_local_data  — snapshot current records
  2. unbound-control <reload_command>  — clear heap (fast-reload on Unbound >= 1.22,
     reload on older versions; reload_command written to keaubnd.json by start.py)
  3. local_datas  — restore snapshot

The reload_command is detected once by start.py (via 'unbound -V') and stored in
keaubnd.json; no per-run capability probe is performed here.

Called by:
  - The kea-ubnd-ddns daemon (via the FastReload SM directive) when the live-path
    NCR mutation counter reaches the configured threshold.
  - The scheduled cron job (configctl keaubnd fast_reload), as a standalone
    heap-reclaim step.  No Kea queries; all records are preserved via snapshot.

Usage:
    fast-reload.py [--config PATH] [--dry-run] [--verbose]
"""

from __future__ import annotations

import argparse
import subprocess
import sys

sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")
from lib import keaubnd_runtime as _rt  # noqa: E402
from lib.keaubnd_sync import setup_logging, unbound_mutation_lock  # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--config",
        default=None,
        help="Path to keaubnd.json (default: /var/run/keaubnd/keaubnd.json)",
    )
    p.add_argument(
        "--dry-run", "-n", action="store_true",
        help="Log what would happen without calling unbound-control",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Log detailed output")
    return p.parse_args()


def main():
    args = parse_args()
    logger = setup_logging(verbose=args.verbose)

    if args.config:
        _rt.init(args.config)

    control = _rt.get_unbound_control()
    conf = _rt.get_unbound_conf()
    reload_cmd = _rt.get_fast_reload_command()

    def uc(*cmd, stdin=None):
        full = [control, "-c", conf] + list(cmd)
        if args.dry_run:
            logger.info("[dry-run] %s", " ".join(full))
            return ""
        r = subprocess.run(
            full, capture_output=True, text=True, timeout=30, input=stdin,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"unbound-control {' '.join(cmd)} failed "
                f"(rc={r.returncode}): {r.stderr.strip()}"
            )
        return r.stdout

    try:
        with unbound_mutation_lock(blocking=True):
            records = uc("list_local_data")
            n = len(records.splitlines()) if records else 0
            logger.info("fast-reload: %d records dumped, running %s", n, reload_cmd)
            uc(reload_cmd)
            uc("local_datas", stdin=records)
        logger.info("fast-reload complete (%d records restored)", n)
    except RuntimeError as e:
        logger.error("%s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

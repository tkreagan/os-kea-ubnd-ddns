# SPDX-License-Identifier: BSD-2-Clause
"""
Snapshot serialisation, archive storage, and weekly diff/summary for the
production monitor; also used by the chaos monkey for its JSON result files.
"""
from __future__ import annotations

import dataclasses
import datetime
import gzip
import json
import pathlib
from typing import Any


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CheckResult:
    name: str
    ok: bool
    details: str = ""
    raw: Any = None

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        if d["raw"] is not None and not isinstance(d["raw"], (str, int, float, bool)):
            try:
                d["raw"] = json.loads(json.dumps(d["raw"]))
            except Exception:
                d["raw"] = str(d["raw"])
        return d


@dataclasses.dataclass
class Snapshot:
    timestamp: str      # ISO-8601
    host: str
    checks: list[CheckResult]
    notes: list[str] = dataclasses.field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.ok]

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "all_ok": self.all_ok,
            "checks": [c.as_dict() for c in self.checks],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        checks = [CheckResult(**c) for c in d.get("checks", [])]
        return cls(
            timestamp=d["timestamp"],
            host=d["host"],
            checks=checks,
            notes=d.get("notes", []),
        )


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------

class Archive:
    """
    Store and retrieve Snapshots as gzipped JSON files under archive_dir.
    Layout: YYYY-MM-DD/HHMMSS_<host>.json.gz
    """

    def __init__(self, archive_dir: pathlib.Path | str):
        self.archive_dir = pathlib.Path(archive_dir).expanduser()

    def save(self, snapshot: Snapshot) -> pathlib.Path:
        ts = datetime.datetime.fromisoformat(snapshot.timestamp)
        date_str = ts.strftime("%Y-%m-%d")
        time_str = ts.strftime("%H%M%S")
        safe_host = snapshot.host.replace(".", "_")
        day_dir = self.archive_dir / date_str
        day_dir.mkdir(parents=True, exist_ok=True)
        path = day_dir / f"{time_str}_{safe_host}.json.gz"
        data = json.dumps(snapshot.as_dict(), indent=2).encode()
        with gzip.open(path, "wb") as f:
            f.write(data)
        return path

    def load(self, path: pathlib.Path) -> Snapshot:
        with gzip.open(path, "rb") as f:
            d = json.loads(f.read())
        return Snapshot.from_dict(d)

    def load_all(self, since: datetime.date | None = None) -> list[Snapshot]:
        snapshots: list[Snapshot] = []
        for gz in sorted(self.archive_dir.rglob("*.json.gz")):
            if since is not None:
                day = gz.parent.name
                try:
                    d = datetime.date.fromisoformat(day)
                    if d < since:
                        continue
                except ValueError:
                    pass
            try:
                snapshots.append(self.load(gz))
            except Exception:
                pass
        return snapshots

    def append_log_lines(self, host: str, date_str: str, lines: bytes) -> pathlib.Path:
        """Append raw log bytes to a per-day log file (for orbison log harvest)."""
        log_dir = self.archive_dir / "logs" / date_str
        log_dir.mkdir(parents=True, exist_ok=True)
        safe_host = host.replace(".", "_")
        path = log_dir / f"{safe_host}.log"
        with open(path, "ab") as f:
            f.write(lines)
            if lines and not lines.endswith(b"\n"):
                f.write(b"\n")
        return path


# ---------------------------------------------------------------------------
# Diff / weekly summary
# ---------------------------------------------------------------------------

class WeeklySummary:
    def __init__(self, snapshots: list[Snapshot]):
        self.snapshots = sorted(snapshots, key=lambda s: s.timestamp)

    def uptime_pct(self) -> dict[str, float]:
        """Return {check_name: pct_ok} across all snapshots."""
        counts: dict[str, list[bool]] = {}
        for snap in self.snapshots:
            for c in snap.checks:
                counts.setdefault(c.name, []).append(c.ok)
        return {name: sum(vals) / len(vals) * 100 for name, vals in counts.items()}

    def flapping_hosts(self) -> list[str]:
        """
        Hosts that appear in some DNS forward-verify checks but not others
        (indicator of intermittent registration).
        """
        seen: dict[str, set[bool]] = {}
        for snap in self.snapshots:
            for c in snap.checks:
                if c.name == "dns_forward_verify" and isinstance(c.raw, list):
                    for item in c.raw:
                        h = item.get("hostname", "")
                        seen.setdefault(h, set()).add(item.get("forward_ok", False))
        return [h for h, states in seen.items() if len(states) > 1]

    def error_summary(self) -> list[dict]:
        """Top errors across all snapshots, sorted by frequency."""
        counts: dict[str, int] = {}
        for snap in self.snapshots:
            for c in snap.checks:
                if not c.ok and c.details:
                    key = c.details[:120]
                    counts[key] = counts.get(key, 0) + 1
        return sorted(
            [{"message": k, "count": v} for k, v in counts.items()],
            key=lambda x: -x["count"],
        )

    def record_count_timeline(self) -> list[dict]:
        """Return [{timestamp, count}] for Unbound local_data count."""
        result = []
        for snap in self.snapshots:
            for c in snap.checks:
                if c.name == "unbound_health" and isinstance(c.raw, dict):
                    count = c.raw.get("local_data_count")
                    if count is not None:
                        result.append({"timestamp": snap.timestamp, "count": count})
        return result

    def stale_orphan_events(self) -> list[dict]:
        """Return snapshots where audit found stale or orphaned records."""
        events = []
        for snap in self.snapshots:
            for c in snap.checks:
                if c.name == "audit_snapshot" and isinstance(c.raw, dict):
                    stale = c.raw.get("stale_count", 0)
                    orphan = c.raw.get("orphan_count", 0)
                    if stale or orphan:
                        events.append({
                            "timestamp": snap.timestamp,
                            "stale": stale,
                            "orphan": orphan,
                        })
        return events

    def render(self) -> str:
        lines = [
            "=" * 60,
            "WEEKLY MONITORING SUMMARY",
            f"Snapshots: {len(self.snapshots)}",
            "=" * 60,
            "",
        ]
        if self.snapshots:
            lines += [
                f"Period: {self.snapshots[0].timestamp[:10]} → "
                f"{self.snapshots[-1].timestamp[:10]}",
                "",
            ]

        lines.append("Service uptime %:")
        for name, pct in sorted(self.uptime_pct().items()):
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            lines.append(f"  {name:<30} {bar} {pct:5.1f}%")

        lines.append("")
        flapping = self.flapping_hosts()
        if flapping:
            lines.append(f"Flapping hosts ({len(flapping)}):")
            for h in sorted(flapping):
                lines.append(f"  {h}")
        else:
            lines.append("Flapping hosts: none")

        lines.append("")
        events = self.stale_orphan_events()
        if events:
            lines.append(f"Stale/orphan events ({len(events)}):")
            for e in events:
                lines.append(
                    f"  {e['timestamp']}  stale={e['stale']}  orphan={e['orphan']}"
                )
        else:
            lines.append("Stale/orphan events: none")

        lines.append("")
        errors = self.error_summary()
        if errors:
            lines.append("Top errors:")
            for e in errors[:10]:
                lines.append(f"  [{e['count']:3d}x]  {e['message']}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chaos monkey result rendering
# ---------------------------------------------------------------------------

def render_chaos_results(results: list[dict]) -> str:
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    errored = sum(1 for r in results if r["status"] == "error")
    skipped = sum(1 for r in results if r["status"] == "skip")
    total = len(results)

    lines = [
        "",
        "=" * 60,
        "CHAOS MONKEY RESULTS",
        "=" * 60,
        f"Total: {total}  Pass: {passed}  Fail: {failed}  "
        f"Error: {errored}  Skip: {skipped}",
        "",
    ]
    for r in results:
        icon = {"pass": "✓", "fail": "✗", "error": "!", "skip": "–"}.get(r["status"], "?")
        lines.append(f"  {icon} [{r['status'].upper():<5}] {r['name']:<35} "
                     f"{r['duration_s']:.1f}s")
        if r.get("failures"):
            for f in r["failures"]:
                lines.append(f"           ↳ {f}")
        if r.get("error"):
            lines.append(f"           ↳ ERROR: {r['error'][:100]}")
    lines.append("")
    return "\n".join(lines)

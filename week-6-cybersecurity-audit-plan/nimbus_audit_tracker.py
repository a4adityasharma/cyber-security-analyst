#!/usr/bin/env python3
"""
nimbus_audit_tracker.py
Persistent Cybersecurity Audit Register & Due-Date Engine

Author:       Aditya Sharma
Organization: Nimbus Retail Solutions (hypothetical, ~450 employees)
Internship:   Cyber Security Analyst Track — Week 6 companion script

Purpose
-------
The Week 6 Cybersecurity Audit Plan defines 10 recurring audit domains
(AUD-01 through AUD-10), each with a review frequency. A plan on paper only
stays true if something actually tracks whether each audit ran on time.
This script IS that tracker: it persists state to a JSON register on disk,
computes each audit's real next-due date from its last completion date and
frequency, and reports overdue / due-soon / on-track status relative to
today's actual date — not a hardcoded quarter.

Design notes
------------
- State is a JSON file (default: audit_register.json) so the register
  survives between runs, can be committed to the repo as a running record,
  and can be inspected/edited by hand if needed.
- Due dates are computed, not stored: next_due = last_completed + frequency.
  This means the register never goes stale just because nobody remembered
  to bump a "current quarter" field.
- No third-party dependencies — stdlib only (argparse, json, datetime,
  csv) — so it runs in any CI runner or grader environment without a
  pip install step.
- Subcommands mirror how a real team would use this day to day: check
  overall status, mark something complete when it happens, see what is
  due this quarter, and export the register for a compliance reviewer.

Usage
-----
    python3 nimbus_audit_tracker.py status
    python3 nimbus_audit_tracker.py status --overdue-only
    python3 nimbus_audit_tracker.py complete AUD-03 --date 2026-09-15
    python3 nimbus_audit_tracker.py calendar
    python3 nimbus_audit_tracker.py export --format csv --out audits.csv

Exit codes: 0 = no overdue audits, 1 = at least one audit is overdue,
2 = could not load/parse the register file.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional

DEFAULT_REGISTER_PATH = Path("audit_register.json")

FREQUENCY_DAYS = {
    "Quarterly": 91,
    "Semi-Annual": 182,
    "Annual": 365,
}

# Grace window before a not-yet-due audit is flagged "due soon" in status output.
DUE_SOON_WINDOW_DAYS = 21

# Seed data — mirrors the Week 6 Cybersecurity Audit Plan (Section 5/6).
# last_completed is intentionally null for a fresh register: the plan has
# been written but no audit cycle has been recorded yet. Run `complete`
# as each audit actually happens to build up real history.
DEFAULT_AUDIT_DOMAINS = [
    {"id": "AUD-01", "domain": "Governance & Policy", "title": "Policy Currency & Ownership Review",
     "owner": "IT Security Team", "frequency": "Annual",
     "framework": "ISO/IEC 27001:2022 Cl. 5.2, 9.2; CIS Control 14", "last_completed": None},
    {"id": "AUD-02", "domain": "Security Awareness", "title": "Training Completion & Effectiveness Review",
     "owner": "Security Awareness Lead", "frequency": "Quarterly",
     "framework": "NIST CSF 2.0 PR.AT; CIS Control 14", "last_completed": None},
    {"id": "AUD-03", "domain": "Vulnerability Management", "title": "Vulnerability Scan & Remediation Verification",
     "owner": "IT Security Team", "frequency": "Quarterly",
     "framework": "CIS Control 7; PCI-DSS 4.0 Req. 11.3", "last_completed": None},
    {"id": "AUD-04", "domain": "Endpoint Configuration", "title": "Endpoint & Configuration Baseline Review",
     "owner": "IT Security Team", "frequency": "Semi-Annual",
     "framework": "CIS Control 4; PCI-DSS 4.0 Req. 4.2.1", "last_completed": None},
    {"id": "AUD-05", "domain": "Access Control", "title": "User Access & Privilege Review",
     "owner": "IT Security Team", "frequency": "Quarterly",
     "framework": "CIS Control 5, 6; ISO/IEC 27001:2022 A.5.18", "last_completed": None},
    {"id": "AUD-06", "domain": "Network Architecture", "title": "Network Segmentation Verification",
     "owner": "IT Security Team", "frequency": "Annual",
     "framework": "CIS Control 12; NIST CSF 2.0 PR.AC", "last_completed": None},
    {"id": "AUD-07", "domain": "Third-Party Risk", "title": "Vendor & Supply-Chain Security Review",
     "owner": "IT Security Team", "frequency": "Annual",
     "framework": "CIS Control 15; ISO/IEC 27001:2022 A.5.19", "last_completed": None},
    {"id": "AUD-08", "domain": "Data Protection", "title": "Data Classification & Handling Review",
     "owner": "IT Security Team", "frequency": "Annual",
     "framework": "PCI-DSS 4.0 Req. 3; ISO/IEC 27001:2022 A.8.10", "last_completed": None},
    {"id": "AUD-09", "domain": "Incident Response", "title": "Incident Response Tabletop Exercise",
     "owner": "IT Security Team + Leadership", "frequency": "Annual",
     "framework": "NIST CSF 2.0 RS; CIS Control 17", "last_completed": None},
    {"id": "AUD-10", "domain": "Backup & Continuity", "title": "Backup Integrity & Restore Test",
     "owner": "IT Security Team", "frequency": "Semi-Annual",
     "framework": "CIS Control 11; NIST CSF 2.0 RC", "last_completed": None},
]


@dataclass
class AuditDomain:
    id: str
    domain: str
    title: str
    owner: str
    frequency: str
    framework: str
    last_completed: Optional[str] = None  # ISO date string or None

    @property
    def frequency_days(self) -> int:
        return FREQUENCY_DAYS[self.frequency]

    def last_completed_date(self) -> Optional[date]:
        if not self.last_completed:
            return None
        return datetime.strptime(self.last_completed, "%Y-%m-%d").date()

    def next_due_date(self, today: date) -> date:
        last = self.last_completed_date()
        if last is None:
            return today  # never completed -> due immediately
        return last + timedelta(days=self.frequency_days)

    def status(self, today: date) -> str:
        due = self.next_due_date(today)
        days_remaining = (due - today).days
        if self.last_completed_date() is None:
            return "NEVER COMPLETED"
        if days_remaining < 0:
            return f"OVERDUE by {-days_remaining}d"
        if days_remaining <= DUE_SOON_WINDOW_DAYS:
            return f"DUE SOON ({days_remaining}d)"
        return f"ON TRACK ({days_remaining}d remaining)"

    def is_overdue(self, today: date) -> bool:
        return self.status(today).startswith("OVERDUE") or self.status(today) == "NEVER COMPLETED"


def load_register(path: Path) -> list[AuditDomain]:
    if not path.exists():
        return [AuditDomain(**d) for d in DEFAULT_AUDIT_DOMAINS]
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"Could not read register at {path}: {exc}") from exc
    return [AuditDomain(**d) for d in raw]


def save_register(path: Path, domains: list[AuditDomain]) -> None:
    path.write_text(json.dumps([asdict(d) for d in domains], indent=2))


def current_quarter(d: date) -> str:
    return f"Q{((d.month - 1) // 3) + 1}"


def cmd_status(args, domains: list[AuditDomain]) -> int:
    today = date.today()
    print("=" * 90)
    print(f"  NIMBUS RETAIL SOLUTIONS — AUDIT STATUS as of {today.isoformat()} ({current_quarter(today)})")
    print("=" * 90)
    print(f"{'ID':<8} {'Title':<42} {'Owner':<24} {'Next Due':<12} {'Status'}")
    print("-" * 90)

    rows = sorted(domains, key=lambda d: d.next_due_date(today))
    overdue_count = 0
    for d in rows:
        st = d.status(today)
        if d.is_overdue(today):
            overdue_count += 1
        if args.overdue_only and not d.is_overdue(today):
            continue
        due = d.next_due_date(today).isoformat()
        print(f"{d.id:<8} {d.title[:41]:<42} {d.owner[:23]:<24} {due:<12} {st}")

    print("-" * 90)
    print(f"  {overdue_count} of {len(domains)} audit domain(s) overdue or never completed.")
    print("=" * 90)
    return 1 if overdue_count > 0 else 0


def cmd_complete(args, domains: list[AuditDomain]) -> int:
    target = next((d for d in domains if d.id.upper() == args.audit_id.upper()), None)
    if target is None:
        print(f"[ERROR] No audit domain with id '{args.audit_id}'. Known IDs: {', '.join(d.id for d in domains)}",
              file=sys.stderr)
        return 2
    completion_date = args.date or date.today().isoformat()
    try:
        datetime.strptime(completion_date, "%Y-%m-%d")
    except ValueError:
        print(f"[ERROR] --date must be YYYY-MM-DD, got '{completion_date}'", file=sys.stderr)
        return 2
    target.last_completed = completion_date
    print(f"[OK] {target.id} ({target.title}) marked complete on {completion_date}.")
    next_due = target.next_due_date(date.today())
    print(f"     Next due: {next_due.isoformat()} (frequency: {target.frequency})")
    return 0


def cmd_calendar(args, domains: list[AuditDomain]) -> int:
    today = date.today()
    year = args.year or today.year
    quarters = {f"Q{n}": (date(year, 3 * n - 2, 1), date(year, 3 * n, 28)) for n in range(1, 5)}

    print("=" * 90)
    print(f"  ROLLING AUDIT CALENDAR — {year} (computed from actual due dates, not a fixed template)")
    print("=" * 90)
    header = f"{'Audit ID':<10}{'Frequency':<14}" + "".join(f"{q:<8}" for q in quarters)
    print(header)
    print("-" * 90)

    for d in domains:
        due = d.next_due_date(today)
        row = f"{d.id:<10}{d.frequency:<14}"
        for q, (start, _end) in quarters.items():
            # Mark a quarter if the computed due date falls within it, projecting
            # forward on the domain's own cadence rather than a hardcoded schedule.
            hit = False
            cursor = due
            for _ in range(6):  # look ahead a few cycles to cover the requested year
                if start.year == cursor.year and start <= cursor <= date(start.year, start.month + 2 if start.month <= 10 else 12, 28):
                    hit = True
                    break
                cursor = cursor + timedelta(days=d.frequency_days)
            row += f"{'X' if hit else '':<8}"
        print(row)

    print("=" * 90)
    return 0


def cmd_export(args, domains: list[AuditDomain]) -> int:
    today = date.today()
    rows = [{
        "id": d.id, "domain": d.domain, "title": d.title, "owner": d.owner,
        "frequency": d.frequency, "framework": d.framework,
        "last_completed": d.last_completed or "",
        "next_due": d.next_due_date(today).isoformat(),
        "status": d.status(today),
    } for d in domains]

    out_path = Path(args.out) if args.out else None

    if args.format == "json":
        payload = json.dumps(rows, indent=2)
        if out_path:
            out_path.write_text(payload)
            print(f"[OK] Wrote {len(rows)} rows to {out_path}")
        else:
            print(payload)
    else:
        target = out_path or Path("audit_export.csv")
        with target.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"[OK] Wrote {len(rows)} rows to {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persistent tracker for the Week 6 Cybersecurity Audit Plan.")
    parser.add_argument("--register", default=str(DEFAULT_REGISTER_PATH),
                         help=f"Path to the JSON register file (default: {DEFAULT_REGISTER_PATH})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="Show current status of all audit domains")
    p_status.add_argument("--overdue-only", action="store_true", help="Only list overdue / never-completed domains")
    p_status.set_defaults(func=cmd_status)

    p_complete = sub.add_parser("complete", help="Mark an audit domain complete")
    p_complete.add_argument("audit_id", help="Audit ID, e.g. AUD-03")
    p_complete.add_argument("--date", help="Completion date as YYYY-MM-DD (default: today)")
    p_complete.set_defaults(func=cmd_complete)

    p_cal = sub.add_parser("calendar", help="Show a projected quarterly calendar for a given year")
    p_cal.add_argument("--year", type=int, help="Year to project (default: current year)")
    p_cal.set_defaults(func=cmd_calendar)

    p_export = sub.add_parser("export", help="Export the register with computed status")
    p_export.add_argument("--format", choices=["csv", "json"], default="csv")
    p_export.add_argument("--out", help="Output file path (default: audit_export.csv or stdout for json)")
    p_export.set_defaults(func=cmd_export)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    register_path = Path(args.register)

    try:
        domains = load_register(register_path)
    except RuntimeError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 2

    result = args.func(args, domains)

    if args.command == "complete":
        save_register(register_path, domains)

    return result


if __name__ == "__main__":
    sys.exit(main())

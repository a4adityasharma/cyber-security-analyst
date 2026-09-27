#!/usr/bin/env python3
"""
Nimbus Shield — Campaign Analytics Engine
Author: Aditya
Task: Week 4 - Security Awareness Campaign Planning (supplementary technical artifact)

Purpose
-------
Computes the KPIs defined in the written Security Awareness Campaign Plan
(Section 3: click rate, report rate; Section 9/Appendix A: repeat-offender
escalation) from a batch of simulated-phishing results, and recommends the
correct remediation action and case-study module per department.

Privacy note
------------
Employee identifiers here are anonymized IDs (e.g. "FIN-001"), not names.
Pairing a real person's name with their phishing-click/report history is
exactly the kind of Restricted-tier personal data the Week 3 Security Policy
Review said requires access controls and encryption — it should not sit in
plain text in a script kept in a public GitHub repository. This script
demonstrates the analytics logic without creating that exposure.

Usage
-----
    python3 nimbus_shield_analytics.py                        # run on built-in demo data
    python3 nimbus_shield_analytics.py --data-file wave1.json  # run on real simulation export
    python3 nimbus_shield_analytics.py --export-json out.json  # also save the computed report
    python3 nimbus_shield_analytics.py --self-test             # run built-in correctness checks
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
from dataclasses import dataclass
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("nimbus_shield")

# KPI targets, from Security Awareness Campaign Plan, Section 3
KPI_TARGETS = {
    "click_rate_pct": 5.0,     # 12-month target: at or below this
    "report_rate_pct": 25.0,   # 12-month target: at or above this
}

# Department -> recommended module, from Campaign Plan Section 4 (Audience Segmentation)
CASE_STUDY_MODULE_MAP = {
    "Finance": "Module 11 — Cross-Industry BEC (Rimasauskas) & Dual-Approval Drill",
    "Customer Support": "Module 3 — Twitter (2020) Vishing & Verification Rules",
    "Engineering / IT": "Modules 2 & 3 — Uber (2022) MFA Fatigue / Twilio (2022) Smishing",
    "Warehouse & Fulfillment": "Module 6 — Physical Security & Tailgating",
    "Marketing": "Module 1 — Brand-Impersonation Phishing & SaaS Credential Reuse",
    "Leadership / Executive": "Module 10 — Whaling & CEO Fraud",
}


@dataclass
class SimulationRecord:
    """One anonymized employee's result in a single phishing-simulation wave."""
    employee_id: str
    department: str
    clicked: bool
    reported: bool
    report_time_minutes: Optional[float] = None
    prior_failures: int = 0  # clicks in EARLIER waves, not counting this one

    def __post_init__(self):
        if not self.employee_id or not self.department:
            raise ValueError("employee_id and department are required.")
        if self.report_time_minutes is not None and self.report_time_minutes < 0:
            raise ValueError(f"{self.employee_id}: report_time_minutes cannot be negative.")
        if self.prior_failures < 0:
            raise ValueError(f"{self.employee_id}: prior_failures cannot be negative.")


def compute_kpis(records: list[SimulationRecord]) -> dict:
    """Core KPI math. Raises ValueError on an empty batch rather than dividing by zero."""
    if not records:
        raise ValueError("Cannot compute KPIs on an empty simulation batch.")
    total = len(records)
    clicks = sum(r.clicked for r in records)
    reports = sum(r.reported for r in records)
    report_times = [r.report_time_minutes for r in records if r.report_time_minutes is not None]

    return {
        "total_employees": total,
        "click_rate_pct": round(clicks / total * 100, 1),
        "report_rate_pct": round(reports / total * 100, 1),
        "avg_report_time_minutes": round(statistics.mean(report_times), 1) if report_times else None,
    }


def kpi_status(value: float, target: float, direction: str) -> str:
    """direction='below' -> lower is better (click rate); 'above' -> higher is better (report rate)."""
    if direction == "below":
        return "ON TARGET" if value <= target else "NEEDS ATTENTION"
    if direction == "above":
        return "ON TARGET" if value >= target else "NEEDS ATTENTION"
    raise ValueError("direction must be 'below' or 'above'.")


def department_breakdown(records: list[SimulationRecord]) -> list[dict]:
    depts = sorted({r.department for r in records})
    result = []
    for dept in depts:
        d_records = [r for r in records if r.department == dept]
        kpis = compute_kpis(d_records)
        kpis["department"] = dept
        kpis["recommended_module"] = CASE_STUDY_MODULE_MAP.get(dept, "General Awareness Track")
        result.append(kpis)
    return result


def remediation_action(total_failures: int) -> str:
    """Maps a cumulative click count to the Campaign Plan's escalation protocol."""
    if total_failures < 1:
        raise ValueError("total_failures must be at least 1 to recommend a remediation action.")
    if total_failures == 1:
        return "Just-in-time 90-second landing-page review (Appendix A.2 debrief message)"
    if total_failures == 2:
        return "Mandatory 15-minute LMS refresher module, due within 5 business days"
    return "Escalate to a 1-on-1 coaching session with the Security Awareness Lead"


def build_report(records: list[SimulationRecord]) -> dict:
    org = compute_kpis(records)
    org["click_rate_status"] = kpi_status(org["click_rate_pct"], KPI_TARGETS["click_rate_pct"], "below")
    org["report_rate_status"] = kpi_status(org["report_rate_pct"], KPI_TARGETS["report_rate_pct"], "above")

    remediation = []
    for r in records:
        if r.clicked:
            total_failures = r.prior_failures + 1
            remediation.append({
                "employee_id": r.employee_id,
                "department": r.department,
                "total_failures": total_failures,
                "action": remediation_action(total_failures),
            })

    return {
        "organization_kpis": org,
        "department_breakdown": department_breakdown(records),
        "remediation_actions": remediation,
    }


def print_report(report: dict) -> None:
    org = report["organization_kpis"]
    print("=" * 78)
    print("NIMBUS SHIELD — CAMPAIGN ANALYTICS ENGINE")
    print("=" * 78)
    print(f"Employees in this simulation wave : {org['total_employees']}")
    print(f"Click rate  : {org['click_rate_pct']:>5.1f}%  (target <= {KPI_TARGETS['click_rate_pct']}%)  [{org['click_rate_status']}]")
    print(f"Report rate : {org['report_rate_pct']:>5.1f}%  (target >= {KPI_TARGETS['report_rate_pct']}%)  [{org['report_rate_status']}]")
    if org["avg_report_time_minutes"] is not None:
        print(f"Avg. time to report : {org['avg_report_time_minutes']} minutes")

    print("\nDEPARTMENT BREAKDOWN")
    print("-" * 78)
    print(f"{'Department':<26}{'Users':>7}{'Click %':>10}{'Report %':>10}   Recommended Module")
    print("-" * 78)
    for d in report["department_breakdown"]:
        print(f"{d['department']:<26}{d['total_employees']:>7}{d['click_rate_pct']:>9.1f}%{d['report_rate_pct']:>9.1f}%   {d['recommended_module']}")

    print("\nREMEDIATION QUEUE")
    print("-" * 78)
    if not report["remediation_actions"]:
        print("No employees clicked in this wave.")
    for a in report["remediation_actions"]:
        print(f"  {a['employee_id']:<10} [{a['department']}] — total failures: {a['total_failures']} -> {a['action']}")
    print("=" * 78)


def load_records_from_json(path: str) -> list[SimulationRecord]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raise ValueError("JSON data file must contain a list of simulation records.")
    return [SimulationRecord(**item) for item in raw]


def demo_records() -> list[SimulationRecord]:
    """Synthetic Month-1 baseline wave, one illustrative record per workforce segment
    from Campaign Plan Section 4. All IDs are anonymized placeholders."""
    return [
        SimulationRecord("FIN-001", "Finance", clicked=False, reported=True, report_time_minutes=7),
        SimulationRecord("FIN-002", "Finance", clicked=True, reported=False, prior_failures=1),
        SimulationRecord("FIN-003", "Finance", clicked=False, reported=False),
        SimulationRecord("CS-001", "Customer Support", clicked=True, reported=False, prior_failures=2),
        SimulationRecord("CS-002", "Customer Support", clicked=True, reported=False),
        SimulationRecord("CS-003", "Customer Support", clicked=False, reported=True, report_time_minutes=14),
        SimulationRecord("WH-001", "Warehouse & Fulfillment", clicked=True, reported=False),
        SimulationRecord("WH-002", "Warehouse & Fulfillment", clicked=False, reported=False),
        SimulationRecord("ENG-001", "Engineering / IT", clicked=False, reported=True, report_time_minutes=3),
        SimulationRecord("ENG-002", "Engineering / IT", clicked=False, reported=True, report_time_minutes=5),
        SimulationRecord("MKT-001", "Marketing", clicked=True, reported=False),
        SimulationRecord("EXEC-001", "Leadership / Executive", clicked=False, reported=True, report_time_minutes=9),
    ]


def _run_self_tests() -> None:
    """Built-in correctness checks — run with --self-test. No pytest dependency required."""
    sample = [
        SimulationRecord("A", "X", clicked=True, reported=False),
        SimulationRecord("B", "X", clicked=False, reported=True, report_time_minutes=10),
    ]
    kpis = compute_kpis(sample)
    assert kpis["click_rate_pct"] == 50.0, "click rate calculation failed"
    assert kpis["report_rate_pct"] == 50.0, "report rate calculation failed"
    assert kpis["avg_report_time_minutes"] == 10.0, "avg report time calculation failed"

    assert kpi_status(4.0, 5.0, "below") == "ON TARGET"
    assert kpi_status(6.0, 5.0, "below") == "NEEDS ATTENTION"
    assert kpi_status(30.0, 25.0, "above") == "ON TARGET"
    assert kpi_status(20.0, 25.0, "above") == "NEEDS ATTENTION"

    assert remediation_action(1).startswith("Just-in-time")
    assert remediation_action(2).startswith("Mandatory")
    assert remediation_action(3).startswith("Escalate")

    for bad_call, label in [
        (lambda: compute_kpis([]), "empty batch"),
        (lambda: remediation_action(0), "zero failures"),
        (lambda: SimulationRecord("", "X", clicked=False, reported=False), "empty employee_id"),
        (lambda: SimulationRecord("A", "X", clicked=False, reported=False, report_time_minutes=-1), "negative report time"),
        (lambda: kpi_status(1.0, 2.0, "sideways"), "invalid direction"),
    ]:
        try:
            bad_call()
            raise AssertionError(f"expected ValueError for: {label}")
        except ValueError:
            pass

    logger.info("All self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Nimbus Shield campaign analytics engine.")
    parser.add_argument("--data-file", type=str, help="Path to a JSON file of simulation records. Uses built-in demo data if omitted.")
    parser.add_argument("--export-json", type=str, help="Write the computed report to this JSON file.")
    parser.add_argument("--self-test", action="store_true", help="Run built-in correctness tests and exit.")
    args = parser.parse_args()

    if args.self_test:
        _run_self_tests()
        return 0

    try:
        records = load_records_from_json(args.data_file) if args.data_file else demo_records()
    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError) as e:
        logger.error(f"Could not load simulation data: {e}")
        return 1

    try:
        report = build_report(records)
    except ValueError as e:
        logger.error(f"Could not build report: {e}")
        return 1

    print_report(report)

    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report exported to {args.export_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
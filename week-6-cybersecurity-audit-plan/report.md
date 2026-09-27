# Cybersecurity Audit Plan
### Ongoing Audit Strategy for Nimbus Retail Solutions

| Field | Value |
|---|---|
| ** ** | Cybersecurity Audit Plan |
| **Subject Organization** | Nimbus Retail Solutions (hypothetical, ~450 employees, e-commerce/retail) |
| **Version** | 1.0 |
| **Prepared By** | Aditya Sharma \| Yuva Intern Program |
| **Date** | Week 6 Task Submission (Final) |
| **Frameworks Referenced** | ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls v8, PCI-DSS v4.0 |
| **Related Documents** | Completes a four-part series: Week 3 Security Policy Review, Week 4 Security Awareness Campaign Plan, [Week 5 Vulnerability Assessment Report](./Week5_Vulnerability_Assessment_Report.md) |
| **Classification** | Confidential — Internal Use Only |
| **Companion Script** | [`nimbus_audit_tracker.py`](./nimbus_audit_tracker.py) — persistent, date-driven tracker for all 10 audit domains below |

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Purpose & Objectives](#2-purpose--objectives)
3. [Audit Scope](#3-audit-scope)
4. [Audit Methodology](#4-audit-methodology)
5. [Audit Areas](#5-audit-areas)
6. [Audit Schedule](#6-audit-schedule)
7. [Roles & Responsibilities](#7-roles--responsibilities)
8. [Finding Lifecycle & Reporting](#8-finding-lifecycle--reporting)
9. [Recommendations & Next Steps](#9-recommendations--next-steps)
10. [Conclusion](#10-conclusion)

---

## 1. Executive Summary

This plan defines a recurring cybersecurity audit program for Nimbus Retail Solutions. It is the fourth and final deliverable in this internship's security series: the Week 3 Security Policy Review assessed policy maturity (1.35 out of 5.0, with a 3.74 target), the Week 4 Security Awareness Campaign Plan addressed human risk, and the Week 5 Vulnerability Assessment Report identified 13 technical findings across the environment. None of those programs is self-sustaining on its own — policies drift out of date, training effectiveness fades, and newly introduced systems create new vulnerabilities. This audit plan is the governance layer that keeps all three current and verifies, on a fixed cadence, that stated controls are actually operating as described.

The plan defines nine domains split into **ten audit procedures (AUD-01 through AUD-10)**, each assigned an owner, a review frequency, and a specific procedure. Audits are scheduled across a rolling annual calendar so that no domain goes more than 12 months without review, and the highest-risk domains — vulnerability management and access control — are reviewed quarterly rather than annually. A lightweight audit-finding lifecycle (identify → rate → assign → remediate → verify) ties every audit back to the same CVSS-based severity and SLA structure introduced in the Week 5 report, so findings from different audits stay comparable over time.

The plan is designed to be feasible for an organization of Nimbus's size (~450 employees) with a small IT security function: most procedures reuse tools and roles already recommended in Weeks 3–5, rather than assuming new headcount or an external audit firm on retainer, though an annual independent/third-party audit is retained for the highest-stakes domains (Section 6).

---

## 2. Purpose & Objectives

The purpose of this audit plan is to establish a repeatable, evidence-based process for verifying that Nimbus's security controls — policy, technical, and human — remain effective over time, rather than being assessed once and assumed to hold. Specific objectives:

- **Detect control drift:** policies that are outdated, technical controls that have been quietly disabled or misconfigured, and training that has lost effectiveness.
- **Re-verify prior findings:** confirm that Week 5 vulnerability findings and Week 3 policy gaps were actually remediated, not just marked closed.
- **Surface new risk introduced by change:** new vendors, new systems, new integrations, and staff turnover all change the risk picture between assessments.
- **Provide auditable evidence** for compliance obligations relevant to a retail/e-commerce business handling payment data (PCI-DSS) and customer PII.
- **Give leadership a single, recurring view** of security posture trend over time, rather than a point-in-time snapshot.

---

## 3. Audit Scope

### 3.1 In Scope

| Domain | Carried Forward From |
|---|---|
| Governance & policy | Week 3 Security Policy Review |
| Security awareness & training effectiveness | Week 4 Security Awareness Campaign Plan |
| Technical vulnerability & patch management | Week 5 Vulnerability Assessment Report |
| Access control & identity management | New — not directly audited in Weeks 3–5 |
| Network architecture & segmentation | Week 5 (VULN-07 flat network finding) |
| Third-party / vendor risk | Week 5 (VULN-11 payment SDK finding) |
| Data protection & classification | Week 3 (Data Classification domain) |
| Incident response readiness | New — not directly audited in Weeks 3–5 |
| Backup, recovery & business continuity | New — not directly audited in Weeks 3–5 |

### 3.2 Out of Scope

Physical/facility security, HR background-check processes, and legal/contractual review of vendor agreements are acknowledged as adjacent risk areas but are out of scope for this audit plan; they are recommended as a separate compliance workstream (see Section 9).

---

## 4. Audit Methodology

Each audit area follows a consistent four-step procedure, so results are comparable across domains and over time:

1. **Evidence collection** — configuration exports, log samples, policy documents, training completion records, or scan results, pulled directly from source systems rather than self-reported.
2. **Control testing** — walkthrough or technical test confirming the control operates as documented (e.g., attempting a login with a disabled account, checking that a patch SLA was actually met, not just recorded as met).
3. **Finding rating** — gaps are rated using the same Critical/High/Medium/Low scale and SLA structure defined in the Week 5 report, so audit findings and vulnerability findings share one severity language.
4. **Reporting & tracking** — findings are logged in a central audit-tracking register (owner, target date, status) and reviewed at the next quarterly security review meeting until closed. In practice this register is [`nimbus_audit_tracker.py`](./nimbus_audit_tracker.py)'s JSON store, not a static spreadsheet.

Audits are a mix of internal (self-assessment by the IT Security Team against a checklist) and, for the highest-stakes domains, independent (performed by a party outside the team responsible for the control, or an external firm) — specified per area below and summarized in Section 6.

---

## 5. Audit Areas

### 5.1 Governance & Policy

#### AUD-01 — Policy Currency & Ownership Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Annual** | ISO/IEC 27001:2022 Cl. 5.2, 9.2; CIS Control 14 |

**Objective:** Confirm every policy identified in the Week 3 Security Policy Review has a named owner, a documented review date, and reflects current practice rather than an outdated baseline.

**In scope:**
- Acceptable Use, Data Classification, Access Control, Incident Response, and Vendor Management policies
- Policy review/approval dates and version history
- Gaps between written policy and observed practice

**Audit procedure:** Compare each policy's stated review cycle against its actual last-updated date; interview policy owners to confirm the control described is still in effect; re-score policy maturity against the Week 3 rubric to track progress toward the 3.74 target.

**Evidence collected:** Policy documents with version history, sign-off records, updated maturity scorecard.

### 5.2 Security Awareness & Training

#### AUD-02 — Training Completion & Effectiveness Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| Security Awareness Lead | **Quarterly** | NIST CSF 2.0 PR.AT; CIS Control 14 |

**Objective:** Verify the Week 4 awareness campaign is actually reaching staff and reducing risk, not just running.

**In scope:**
- Training completion rates by department
- Phishing-simulation click-through and report rates
- Repeat-offender tracking and escalation

**Audit procedure:** Pull completion and phishing-simulation metrics from the training platform against the KPIs defined in the Week 4 report; sample interview a small group of staff across departments to check retention, not just click-through.

**Evidence collected:** Quarterly KPI dashboard, phishing simulation results, sampled interview notes.

### 5.3 Technical Vulnerability & Patch Management

#### AUD-03 — Vulnerability Scan & Remediation Verification
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Quarterly** | CIS Control 7; PCI-DSS 4.0 Req. 11.3 |

**Objective:** Confirm the recurring scanning program recommended in Week 5 (VULN-12) is actually running, and that prior findings (VULN-01 through VULN-13) were remediated within their SLA, not just marked closed.

**In scope:**
- Authenticated vulnerability scans of all internet-facing and internal assets
- Re-verification of the 13 Week 5 findings using `nimbus_vuln_verify.py`
- Patch-compliance percentage from the centralized patch-management platform

**Audit procedure:** Run the scheduled scan; cross-check each previously Critical/High finding for closure evidence rather than accepting a status field alone; recalculate mean time-to-remediate and compare against the Verizon DBIR benchmarks cited in Week 5.

**Evidence collected:** Scan reports, remediation evidence per finding, patch-compliance report.

#### AUD-04 — Endpoint & Configuration Baseline Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Semi-Annual** | CIS Control 4; PCI-DSS 4.0 Req. 4.2.1 |

**Objective:** Confirm endpoints and key infrastructure (VPN, load balancer, cloud storage) still match the hardened configuration recommended in Week 5, rather than reverting over time.

**In scope:**
- TLS configuration on customer-facing endpoints
- VPN appliance firmware and MFA enforcement
- Cloud storage bucket access-control settings
- HTTP security headers

**Audit procedure:** Re-run `nimbus_vuln_verify.py` from the Week 5 report; sample a subset of endpoints for patch level and agent health.

**Evidence collected:** Configuration scan output, endpoint compliance report.

### 5.4 Access Control & Identity

#### AUD-05 — User Access & Privilege Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Quarterly** | CIS Control 5, 6; ISO/IEC 27001:2022 A.5.18 |

**Objective:** Confirm access rights match current job roles and that former employees' and contractors' access has been fully revoked.

**In scope:**
- Active Directory / identity-provider account list vs. current HR roster
- Administrative and privileged account inventory
- MFA enrollment status for all remote-access and admin accounts

**Audit procedure:** Reconcile the full account list against the HR-confirmed active-employee roster; flag any account not tied to a current employee or approved service; confirm MFA enrollment against the Week 3 report's authentication recommendation.

**Evidence collected:** Access review sign-off sheet, orphaned-account remediation log, MFA enrollment report.

### 5.5 Network Architecture

#### AUD-06 — Network Segmentation Verification
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Annual** | CIS Control 12; NIST CSF 2.0 PR.AC |

**Objective:** Confirm the corporate/warehouse network segmentation recommended in Week 5 (VULN-07) has been implemented and continues to restrict traffic as intended.

**In scope:**
- VLAN configuration between corporate IT and warehouse OT
- Firewall rules governing inter-segment traffic
- Any new systems added to the network since the last review

**Audit procedure:** Review firewall rule sets and VLAN configs against the intended architecture; attempt a controlled connectivity test between segments to confirm restrictions hold in practice, not just on paper.

**Evidence collected:** Network diagrams, firewall rule export, segmentation test results.

### 5.6 Third-Party & Vendor Risk

#### AUD-07 — Vendor & Supply-Chain Security Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Annual** | CIS Control 15; ISO/IEC 27001:2022 A.5.19 |

**Objective:** Confirm third-party components (e.g., the payment-gateway SDK flagged in Week 5, VULN-11) and vendor access remain current and that vendors meet Nimbus's security expectations.

**In scope:**
- Software bill of materials (SBOM) for the checkout flow
- Vendor security questionnaires / attestations on file
- Third-party remote-access accounts and their scope

**Audit procedure:** Compare SBOM component versions against vendor-published current releases; confirm each active vendor has a signed security attestation on file; review third-party account access against least-privilege expectations.

**Evidence collected:** SBOM report, vendor attestation log, third-party access review.

### 5.7 Data Protection

#### AUD-08 — Data Classification & Handling Review
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Annual** | PCI-DSS 4.0 Req. 3; ISO/IEC 27001:2022 A.8.10 |

**Objective:** Confirm customer PII and payment data are stored, transmitted, and retained in line with the Week 3 Data Classification policy.

**In scope:**
- Cloud storage and database access controls for classified data
- Data retention settings against policy-defined retention periods
- Encryption status of data at rest and in transit

**Audit procedure:** Sample a set of data stores against the classification policy; confirm encryption and access-control settings; check retention settings against the documented schedule and flag any data held beyond policy.

**Evidence collected:** Data inventory sample, encryption/retention configuration evidence.

### 5.8 Incident Response Readiness

#### AUD-09 — Incident Response Tabletop Exercise
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team + Leadership | **Annual** | NIST CSF 2.0 RS; CIS Control 17 |

**Objective:** Confirm the incident response plan referenced in the Week 3 policy review actually works under a realistic scenario, and that roles are understood before a real incident forces the question.

**In scope:**
- Incident response plan and escalation contact list currency
- Roles and responsibilities across IT, leadership, and communications
- A simulated scenario (e.g., the VULN-08 VPN compromise scenario from Week 5)

**Audit procedure:** Run a facilitated tabletop exercise using a realistic scenario drawn from the Week 5 findings; document decision points, gaps in the plan, and time-to-decision; update the plan based on lessons learned.

**Evidence collected:** Tabletop exercise notes, updated incident response plan, after-action report.

### 5.9 Backup, Recovery & Continuity

#### AUD-10 — Backup Integrity & Restore Test
| Owner | Frequency | Framework Reference |
|---|---|---|
| IT Security Team | **Semi-Annual** | CIS Control 11; NIST CSF 2.0 RC |

**Objective:** Confirm backups of critical systems (order database, WMS, e-commerce platform) exist, are protected from the same threats as production, and can actually be restored.

**In scope:**
- Backup schedule and retention for critical systems
- Backup isolation from production credentials (ransomware resilience)
- A live restore test of at least one critical system

**Audit procedure:** Verify backup job success logs for the review period; confirm backups are not reachable using standard production credentials; perform a restore test to a non-production environment and measure recovery time against any documented RTO/RPO targets.

**Evidence collected:** Backup job logs, restore test results, recovery time measurement.

---

## 6. Audit Schedule

Audit frequency is risk-weighted: domains tied to Critical/High findings in Week 5, or that change frequently (access, patching), are reviewed more often than stable governance domains. The rolling annual calendar below assumes an audit cycle starting in Q1; adjust to the organization's actual fiscal calendar. **`nimbus_audit_tracker.py`** computes each domain's actual next-due date from its real completion history — the table below is the initial target schedule, not the live source of truth.

| Audit Area | Frequency | Q1 | Q2 | Q3 | Q4 |
|---|---|:---:|:---:|:---:|:---:|
| AUD-01 Policy Currency & Ownership | Annual | | | | ● |
| AUD-02 Training Completion & Effectiveness | Quarterly | ● | ● | ● | ● |
| AUD-03 Vulnerability Scan & Remediation | Quarterly | ● | ● | ● | ● |
| AUD-04 Endpoint & Configuration Baseline | Semi-Annual | ● | | ● | |
| AUD-05 User Access & Privilege Review | Quarterly | ● | ● | ● | ● |
| AUD-06 Network Segmentation Verification | Annual | | ● | | |
| AUD-07 Vendor & Supply-Chain Review | Annual | | | ● | |
| AUD-08 Data Classification & Handling | Annual | ● | | | |
| AUD-09 Incident Response Tabletop | Annual | | | ● | |
| AUD-10 Backup Integrity & Restore Test | Semi-Annual | | ● | | ● |

An independent, external audit — covering PCI-DSS compliance scope and a re-test of the Week 5 Critical findings — is recommended annually in Q4, once internal audits AUD-01 through AUD-10 have completed a full cycle, so external findings can be compared against the internal program's own results.

---

## 7. Roles & Responsibilities

| Role | Audit Responsibilities |
|---|---|
| **IT Security Team** | Owns and executes AUD-01, AUD-03 through AUD-08, AUD-10; maintains the central audit-tracking register; escalates overdue findings. |
| **Security Awareness Lead** | Owns AUD-02; reports quarterly training KPIs alongside audit results. |
| **Department Managers** | Confirm access-review accuracy for their team (AUD-05); participate in the incident response tabletop (AUD-09). |
| **Leadership / Executive Sponsor** | Reviews audit register quarterly; approves budget for findings requiring investment; participates in AUD-09 tabletop. |
| **External Auditor (annual, Q4)** | Performs independent PCI-DSS scope audit and re-tests prior Critical findings; reports directly to leadership. |

---

## 8. Finding Lifecycle & Reporting

Every audit finding, regardless of which of the nine areas it comes from, moves through the same lifecycle so the program produces one consistent view of risk over time:

1. **Identify** — finding logged in the central audit-tracking register with the audit ID, area, and evidence reference.
2. **Rate** — severity assigned using the Critical/High/Medium/Low scale and SLA from the Week 5 report (14/30/90/180 days).
3. **Assign** — an owner and target remediation date are set at the time the finding is logged, not after the fact.
4. **Remediate** — owner implements the fix and attaches evidence (config export, screenshot, sign-off) to the register.
5. **Verify** — a second reviewer (not the finding's owner) confirms the fix before the finding is marked closed.

A summary of open/closed findings, aged by severity, is presented at a quarterly security review meeting attended by the IT Security Team and an executive sponsor — run `python3 nimbus_audit_tracker.py status` ahead of that meeting for a live view.

---

## 9. Recommendations & Next Steps

- Stand up the central audit-tracking register (`nimbus_audit_tracker.py`) before the next scheduled audit — AUD-02 and AUD-03 are quarterly and due soonest.
- Formally assign the audit ownership in Section 7 to named individuals, not just roles, within 30 days.
- Schedule the first AUD-09 incident response tabletop within one quarter — it is currently the least-tested control in the program and directly rehearses the VULN-08 VPN scenario from Week 5.
- Scope a follow-on review of physical security, HR background-check processes, and vendor contract/legal terms, identified in Section 3.2 as adjacent but out of scope here.
- Re-run this plan's Section 6 schedule annually and adjust frequencies based on that year's actual finding volume — a quiet quarter can shift a domain from quarterly to semi-annual, and a bad one should do the reverse.

---

## 10. Conclusion

This audit plan closes the four-part security baseline built across this internship: the Week 3 Security Policy Review established what Nimbus's controls should be, the Week 4 Security Awareness Campaign Plan addressed the human layer, the Week 5 Vulnerability Assessment Report tested what was actually true on the ground, and this plan defines how the organization keeps re-testing that truth on a fixed, risk-weighted schedule rather than treating any of the prior three reports as a one-time exercise.

The program is deliberately sized to Nimbus's ~450-employee scale: it reuses the roles, tools, and severity language already established in Weeks 3–5 rather than requiring new headcount, while still reserving an annual independent audit for the domains — payment data and the Week 5 Critical findings — where an internal-only check is not sufficient assurance on its own.

---
*End of Document*

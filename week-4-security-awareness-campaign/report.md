# Week 4: Security Awareness Campaign Planning
### Campaign Name: "Nimbus Shield" — Nimbus Retail Solutions

* **Author:** Aditya Sharma
* **Organization:** Nimbus Retail Solutions (~450 employees)
* **Track:** Cyber Security Analyst Intern
* **Deliverables:** [Word Document (.docx)](./Aditya_Sharma_Week4_Security_Awareness_Campaign.docx) | [Python Tool (`nimbus_shield_analytics.py`)](./nimbus_shield_analytics.py)

---

## 1. Executive Summary & KPIs

Designed to elevate the Security Awareness Training maturity domain from **1.5/5.0** (identified in Week 3 Review) to a structured 12-month program.

### Core 12-Month KPI Targets
* **Phishing Click Rate:** Reduce from 33% (baseline) to **< 5%**.
* **Phishing Report Rate:** Raise from near-zero to **> 25%**.
* **Annual Refresher Completion:** Achieve **100%** across all 450 staff.

---

## 2. Threat Data & Case Study Integrations

1. **Twitter (2020) Vishing Attack:** Tailored to Customer Support to prevent phone-based identity resets.
2. **Uber (2022) MFA Fatigue:** Integrated for IT & Engineering to eliminate prompt exhaustion.
3. **Rimasauskas BEC Fraud (2019):** Applied to Finance for out-of-band wire change verification.
4. **Twilio (2022) Smishing:** Taught org-wide to address SMS-based credential harvesting.

---

## 3. Python Telemetry Script Execution

Run the custom analytics tool to calculate departmental click rates and assign targeted remediation:

```bash
python3 nimbus_shield_analytics.py
# Week 3 Technical Report: Security Policy Review

* **Track:** Cyber Security Analyst Intern
* **Audited Entity:** Nimbus Retail Solutions (~450 Employees, Hybrid E-Commerce Retailer)[cite: 2]
* **Target Baselines:** NIST CSF 2.0, ISO/IEC 27001:2022, CIS Controls v8, PCI-DSS v4.0[cite: 2]
* **Deliverables:** `report.md`, `Aditya_Sharma_Week3_Security_Policy_Review.docx`, `policy_audit_tool.py`[cite: 2]

---

## 1. Executive Summary

Nimbus Retail Solutions currently operates at an average cybersecurity policy maturity of 1.35 out of 5.0 (Initial/Ad-hoc tier) across ten evaluated domains[cite: 2]. This falls significantly short of the 3.0 (Defined) baseline required for an organization processing customer payment card data and personal information[cite: 2]. Three essential domains—Data Classification, Monitoring & Logging, and Third-Party Management—contain zero documented policies[cite: 2].

Applying the targeted controls outlined in this review will elevate the projected maturity to 3.74 out of 5.0 (+2.39 lift), mitigating the primary attack vectors: credential-based account takeover, unmonitored lateral movement, and third-party supply chain compromise[cite: 2].

---

## 2. Organizational Context & Scope

* **Workforce:** ~450 employees across Customer Support, Warehouse/Fulfillment, Marketing, Engineering, and Finance (60% office, 40% remote/field)[cite: 2].
* **Data Footprint:** Customer PII, order histories, payment card data (tokenized), and employee HR records[cite: 2].
* **Infrastructure:** Cloud-hosted e-commerce application, on-premise warehouse management systems, and third-party SaaS platforms[cite: 2].
* **Regulatory Mandates:** PCI-DSS v4.0, DPDP Act 2023, and GDPR[cite: 2].
* **Incident History:** 1 phishing-driven account compromise within the trailing 12 months with no post-incident root cause analysis documented[cite: 2].

---

## 3. Policy Review & Gap Analysis

### 3.1 Password & Authentication
* **Current Language:** *"Employees must choose a password that is at least 8 characters long and contains at least one number. Passwords must be changed every 180 days."*[cite: 2]
* **Identified Flaw:** Falls below NIST SP 800-63B guidelines[cite: 2]. Forced 180-day rotations create predictable incremental variations, while multi-factor authentication (MFA) is entirely omitted[cite: 2].
* **Supporting Data:** Verizon 2025 DBIR findings show that stolen/weak credentials represent the leading initial access vector, and users reuse passwords across services 51% of the time[cite: 2].
* **Revised Policy Clause:** Passwords must be at least 12 characters long (14 for administrator and finance accounts) and screened dynamically at creation against breach databases[cite: 2]. Mandatory arbitrary rotations are abolished[cite: 2]. Phishing-resistant MFA is required for all access to email, e-commerce admin panels, payment environments, and VPN connections[cite: 2].
* **Maturity Shift:** 1.5 → 4.0[cite: 2]

### 3.2 Access Control & Offboarding
* **Current Language:** *"All new employees are granted access to the shared company drive as part of onboarding. Access is reviewed if a manager requests a change."*[cite: 2]
* **Identified Flaw:** Blanket access violates least privilege[cite: 2]. Reviews are reactive rather than scheduled, allowing privilege creep and unmanaged former-employee credentials[cite: 2].
* **Supporting Data:** IBM’s 2025 Cost of a Data Breach Report identifies malicious insider breaches as the costliest attack path, averaging $4.92 million per incident[cite: 2].
* **Revised Policy Clause:** System and folder permissions are granted via Role-Based Access Control (RBAC) under least privilege[cite: 2]. System access must be revoked within 4 business hours of employee departure[cite: 2]. Data owners must recertify user permissions on a quarterly schedule[cite: 2].
* **Maturity Shift:** 1.5 → 3.8[cite: 2]

### 3.3 Data Classification & Handling
* **Current Language:** *No policy exists.*[cite: 2]
* **Identified Flaw:** Employees have no framework to decide whether data can be shared or exported, triggering a direct non-compliance finding under PCI-DSS v4.0[cite: 2].
* **Supporting Data:** Unclassified environments prevent automated Data Loss Prevention (DLP) engines from detecting and blocking exfiltration of cardholder records[cite: 2].
* **Revised Policy Clause:** All organizational data must be tagged at creation under a 3-tier scheme: Public, Internal, or Restricted[cite: 2]. Restricted assets (cardholder data, PII) must enforce AES-256 encryption at rest, TLS 1.3 in transit, and may never reside on personal storage[cite: 2].
* **Maturity Shift:** 1.0 → 3.5[cite: 2]

### 3.4 Incident Response
* **Current Language:** *"If you notice anything suspicious on your computer, please let the IT Manager know as soon as possible."*[cite: 2]
* **Identified Flaw:** Single point of failure with no triage matrix, escalation SLAs, containment procedures, or regulatory notification timelines[cite: 2].
* **Supporting Data:** IBM reports the 2025 average breach lifecycle is 241 days; unstructured notification paths correlate directly with delayed containment and higher financial loss[cite: 2].
* **Revised Policy Clause:** Security anomalies must be submitted immediately via a 24/7 hotline or monitored alias[cite: 2]. Events must be triaged into SEV-1 through SEV-4 within 30 minutes, triggering standardized containment, eradication, and post-mortem procedures[cite: 2].
* **Maturity Shift:** 1.0 → 4.2[cite: 2]

### 3.5 Remote Work & BYOD
* **Current Language:** *"Employees may use their personal phone or laptop to check company email and access shared files when working outside the office."*[cite: 2]
* **Identified Flaw:** Zero technical baselines (screen lock, storage encryption, patch levels) required on non-corporate hardware touching enterprise data[cite: 2].
* **Supporting Data:** Verizon 2025 DBIR details that 46% of systems compromised by credential-stealing malware were unmanaged personal devices[cite: 2].
* **Revised Policy Clause:** Personal hardware may only access company email and Internal assets after enrolling in enterprise MDM/MAM with storage encryption and current OS patch levels verified[cite: 2]. Restricted data is blocked entirely from unmanaged hardware[cite: 2].
* **Maturity Shift:** 1.8 → 3.7[cite: 2]

### 3.6 Third-Party & Vendor Risk
* **Current Language:** *No policy exists.*[cite: 2]
* **Identified Flaw:** No assessment of vendor security controls prior to onboarding, no contractual breach notification requirements, and no regular access audits[cite: 2].
* **Supporting Data:** IBM 2025 findings show supply chain compromises are the second most prevalent initial vector at 15% of all breaches[cite: 2].
* **Revised Policy Clause:** Third parties requiring data or network access must undergo formal risk assessments prior to onboarding[cite: 2]. Contracts must mandate notification within 72 hours of any security event, and access must be recertified annually[cite: 2].
* **Maturity Shift:** 1.0 → 3.4[cite: 2]

### 3.7 Security Awareness Training
* **Current Language:** *"All new hires receive a security overview as part of their first-week orientation."*[cite: 2]
* **Identified Flaw:** One-time onboarding with no continuous testing, phishing simulations, or role-tailored awareness training[cite: 2].
* **Supporting Data:** Phishing remains the single most common breach vector in 2025 (16% of total incidents)[cite: 2].
* **Revised Policy Clause:** All personnel must complete annual refresher training[cite: 2]. Phishing simulations will run quarterly with tracked click-through and reporting metrics, complemented by targeted training for Finance and Customer Support teams[cite: 2].
* **Maturity Shift:** 1.5 → 3.9[cite: 2]

### 3.8 Monitoring & Logging
* **Current Language:** *No policy exists.*[cite: 2]
* **Identified Flaw:** Security telemetry is not centralized or retained, making proactive detection impossible and foreclosing post-incident digital forensics[cite: 2].
* **Supporting Data:** Organizations without centralized logging take significantly longer to identify compromises, often learning of breaches only from external third parties[cite: 2].
* **Revised Policy Clause:** Authentication events, administrator activity, and access to Restricted tiers must be forwarded to a central SIEM and retained for 12 months[cite: 2]. Real-time alerts must trigger on impossible-travel logins, mass exfiltration, and privilege escalation[cite: 2].
* **Maturity Shift:** 1.0 → 3.6[cite: 2]

### 3.9 Physical Security
* **Current Language:** *"All staff are issued an access badge. Visitors must sign in at the front desk."*[cite: 2]
* **Identified Flaw:** Badge revocation is decoupled from offboarding; visitors are unescorted in warehouse/fulfillment areas where shipping and inventory screens are visible[cite: 2].
* **Supporting Data:** Former-employee access cards and unmonitored visitors represent common operational audit failures in fulfillment facilities with high staff turnover[cite: 2].
* **Revised Policy Clause:** Badge privileges terminate within 4 business hours of employee separation[cite: 2]. Visitors must wear distinct temporary passes and remain escorted in warehouse, server, and sensitive spaces[cite: 2]. Unattended workstations must auto-lock after 5 minutes[cite: 2].
* **Maturity Shift:** 2.0 → 3.5[cite: 2]

### 3.10 Backup & Business Continuity
* **Current Language:** *"IT performs backups of critical systems periodically."*[cite: 2]
* **Identified Flaw:** Undefined frequencies, lack of Recovery Time (RTO) or Recovery Point (RPO) objectives, and no protection against backup encryption[cite: 2].
* **Supporting Data:** In 2025, 63% of ransomware victims refused to pay ransoms, depending instead on viable, immutable offline snapshots for recovery[cite: 2].
* **Revised Policy Clause:** Critical applications must execute backups meeting predefined RPO/RTO metrics[cite: 2]. At least one backup copy must be stored immutably or air-gapped offline, with restoration integrity drills executed quarterly[cite: 2].
* **Maturity Shift:** 1.2 → 3.8[cite: 2]

---

## 4. Maturity Assessment & Scorecard

| # | Domain Evaluated | Baseline Score | Target Score | Net Variance |
| :-: | :--- | :-: | :-: | :-: |
| 1 | Password & Authentication | 1.5 | 4.0 | +2.5[cite: 2] |
| 2 | Access Control | 1.5 | 3.8 | +2.3[cite: 2] |
| 3 | Data Classification & Handling | 1.0 | 3.5 | +2.5[cite: 2] |
| 4 | Incident Response | 1.0 | 4.2 | +3.2[cite: 2] |
| 5 | Remote Work / BYOD | 1.8 | 3.7 | +1.9[cite: 2] |
| 6 | Third-Party / Vendor Management | 1.0 | 3.4 | +2.4[cite: 2] |
| 7 | Security Awareness Training | 1.5 | 3.9 | +2.4[cite: 2] |
| 8 | Monitoring & Logging | 1.0 | 3.6 | +2.6[cite: 2] |
| 9 | Physical Security | 2.0 | 3.5 | +1.5[cite: 2] |
| 10 | Backup & Business Continuity | 1.2 | 3.8 | +2.6[cite: 2] |
| **Overall** | **Enterprise Maturity Score** | **1.35 / 5.0** | **3.74 / 5.0** | **+2.39**[cite: 2] |

---

## 5. Risk Heat Map

| Risk Scenario | Likelihood | Impact | Evaluated Severity |
| :--- | :---: | :---: | :---: |
| Account takeover via stolen credentials / lack of MFA[cite: 2] | High | High | **Critical**[cite: 2] |
| Undetected intrusion due to omitted monitoring & logging[cite: 2] | High | High | **Critical**[cite: 2] |
| Regulatory cardholder / PII exposure from missing data tags[cite: 2] | Medium | High | **High**[cite: 2] |
| Uncontained breach expansion from unstructured response plans[cite: 2] | Medium | High | **High**[cite: 2] |
| Data leakage via compromised supply chain vendor[cite: 2] | Medium | Medium | **Medium**[cite: 2] |
| Infostealer exfiltration through unmanaged BYOD laptops[cite: 2] | Medium | Medium | **Medium**[cite: 2] |
| Backup compromise during targeted ransomware events[cite: 2] | Low-Medium | High | **Medium**[cite: 2] |
| Unauthorized access via retained former-employee credentials[cite: 2] | Medium | Low-Medium | **Low-Medium**[cite: 2] |
| Unauthorized entry or screen viewing at fulfillment sites[cite: 2] | Low | Medium | **Low-Medium**[cite: 2] |

---

## 6. Phased Implementation Roadmap

### Phase 1: Days 0–30 (Immediate Threat Containment)
* Enforce phishing-resistant MFA across email, VPN, e-commerce admin, and payment consoles[cite: 2].
* Update password policy to 12-character minimums, check breach dictionaries, and abolish arbitrary 180-day rotations[cite: 2].
* Formalize the 3-tier data classification standard across all business units[cite: 2].
* Implement a mandatory 4-hour SLA for revoking account and badge access upon termination[cite: 2].
* Distribute an interim Incident Response escalation card with severity tiers and contact paths[cite: 2].

### Phase 2: Days 30–90 (Structural Control Deployment)
* Formalize the comprehensive Incident Response Plan and run a simulated tabletop drill[cite: 2].
* Require MDM/MAM enrollment for all personal devices accessing corporate resources[cite: 2].
* Deploy centralized SIEM logging with a 12-month retention policy and high-risk alerting rules[cite: 2].
* Launch quarterly phishing simulations and role-specific training modules[cite: 2].
* Establish RPO/RTO parameters and configure immutable storage repositories for critical backups[cite: 2].

### Phase 3: Days 90–180 (Continuous Governance & Audit)
* Establish third-party security assessments and insert 72-hour breach notice clauses into contracts[cite: 2].
* Transition system permissions entirely to Role-Based Access Control (RBAC) with quarterly audits[cite: 2].
* Perform scheduled backup restoration drills and record SLA outcomes[cite: 2].
* Re-evaluate enterprise posture against the maturity scorecard[cite: 2].

---

## 7. References

* **IBM Security & Ponemon Institute (2025).** *Cost of a Data Breach Report 2025* ($4.44M average breach cost; 241 days average lifecycle; 16% phishing share; 15% supply chain share)[cite: 2].
* **Verizon Enterprise (2025).** *Data Breach Investigations Report (DBIR)* (88% of web application attacks leverage stolen credentials; 46% of infostealer events hit unmanaged devices)[cite: 2].
* **National Institute of Standards and Technology (2024).** *The NIST Cybersecurity Framework (CSF) 2.0* (NIST SP 1300).
* **National Institute of Standards and Technology (2020).** *Digital Identity Guidelines: Authentication and Lifecycle Management* (NIST SP 800-63B).
* **Center for Internet Security (2021).** *CIS Critical Security Controls Version 8 (Implementation Group 1)*.
* **PCI Security Standards Council (2022).** *Payment Card Industry Data Security Standard (PCI-DSS) Requirements and Testing Procedures Version 4.0*.
* **International Organization for Standardization (2022).** *Information security, cybersecurity and privacy protection — Information security management systems* (ISO/IEC 27001:2022).
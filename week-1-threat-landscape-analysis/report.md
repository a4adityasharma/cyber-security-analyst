# Week 1: Cyber Security Threat Landscape Analysis

* **Internship Track:** Cyber Security Analyst
* **Task:** Threat Landscape Analysis
* **Author:** Aditya Sharma
* **Deliverable Format:** Markdown & [Word Document (.docx)](./Aditya_Sharma_Week1_Threat_Landscape_Analysis.docx)

---

## 1. Executive Summary

Over the past few years, the cyber threat landscape has shifted from isolated, opportunistic malware attacks to highly structured, profit-driven cybercrime ecosystems. Organizations today rely heavily on hybrid cloud environments, third-party software, and remote working setups. While this speeds up business operations, it also creates a wider attack surface that is difficult to monitor manually.

This report analyzes current threat vectors, breaking down how modern threat actors breach defenses, move across internal networks, and extract or encrypt sensitive data. By studying recent trends in ransomware, supply chain risks, identity compromise, and cloud exposures, this paper highlights why reactive security is no longer enough and provides actionable mitigation strategies rooted in Zero Trust and proactive vulnerability management.

---

## 2. Key Cyber Threats in the Current Landscape

### 2.1 Ransomware-as-a-Service (RaaS) & Multi-Extortion
Ransomware is no longer just about encrypting a hard drive and asking for Bitcoin. The current industry standard is Ransomware-as-a-Service, where core developers build the malware and sell access to "affiliates" who handle the actual intrusions. 
* **Double and Triple Extortion:** Attackers now steal critical data before deploying encryption. If the victim has backups and refuses to pay the decryption fee, the group threatens to leak proprietary data publicly or launch DDoS attacks against the business until payment is made.

### 2.2 Software Supply Chain Vulnerabilities
Modern applications are assembled rather than built from scratch, relying on hundreds of open-source packages, third-party libraries, and CI/CD automation tools. Attackers target the upstream providers to compromise thousands of downstream victims simultaneously. 
* **Attack Types:** Dependency confusion, typosquatting malicious packages on registries (like npm and PyPI), and exploiting hardcoded credentials inside source code repositories.

### 2.3 AI-Augmented Phishing & Social Engineering
Social engineering remains the easiest way for attackers to get initial access. Attackers use Large Language Models (LLMs) to write grammatically flawless, highly contextual spear-phishing emails that mimic vendor invoices or executive requests. Deepfake voice cloning is also actively used in business email compromise (BEC) attacks to trick finance teams into authorizing wire transfers.

### 2.4 Cloud & Identity Exploitation
With businesses migrating to AWS, Azure, and Google Cloud, misconfigurations have become a massive risk. Weak IAM (Identity and Access Management) rules, unrotated API keys, and publicly exposed storage buckets allow threat actors to perform unauthorized discovery and privilege escalation within minutes of finding a leaked token.

---

## 3. Attack Vectors & Intrusion Lifecycle (MITRE ATT&CK Mapping)

* **Initial Access:**
  * Phishing emails containing malicious PDF/macro attachments or credential harvesting links.
  * Publicly exposed Remote Desktop Protocol (RDP) servers with weak passwords.
  * Exploitation of unpatched vulnerabilities (CVEs) on public-facing web servers.
* **Execution & Persistence:**
  * **Living-off-the-land Binaries (LOLBins):** Using built-in operating system tools (like PowerShell, WMI, or bash) to run malicious code without triggering basic antivirus alerts.
  * **Persistence:** Creating scheduled tasks, modifying registry run keys, or generating rogue administrative user accounts.
* **Lateral Movement & Privilege Escalation:**
  * Extracting plain-text credentials or password hashes from memory using tools like Mimikatz.
  * Pass-the-Hash and Kerberoasting attacks inside Active Directory environments to gain Domain Admin privileges.
* **Exfiltration & Impact:**
  * Compressing sensitive files into password-protected archives and exfiltrating them over encrypted channels (HTTPS, DNS tunneling, or directly to disposable cloud storage).
  * Executing ransomware binaries across all connected endpoints simultaneously using Group Policy Objects (GPOs).

---

## 4. Organizational Impact

* **Operational Disruption:** Critical systems go offline. In manufacturing, healthcare, or financial sectors, unexpected downtime halts customer transactions and daily operations for days or weeks.
* **Direct Financial Damage:** Incident response retainers, digital forensic investigations, legal counsel fees, extortion costs, and system rebuild expenses quickly add up.
* **Regulatory Fines & Compliance Penalties:** Leaking customer or employee personal data triggers mandatory breach reporting under GDPR, HIPAA, or India's DPDP Act, often resulting in heavy regulatory fines.
* **Long-term Reputation Loss:** Customer churn and damaged investor confidence can take years to recover, especially if client data was leaked on the dark web.

---

## 5. Recommended Defensive Strategies

1. **Zero Trust Architecture (ZTA):** Enforce the principle of least privilege. No user or device should be trusted by default, even if they are inside the corporate network perimeter.
2. **Phishing-Resistant MFA:** Implement hardware security keys (FIDO2/WebAuthn) or authenticator apps, deprecating SMS-based OTPs which are vulnerable to SIM swapping and reverse-proxy phishing kits.
3. **Automated Patch & Vulnerability Management:** Maintain an accurate asset inventory and run continuous vulnerability scans. Prioritize patching based on Known Exploited Vulnerabilities (KEV) rather than just CVSS scores.
4. **Endpoint Detection and Response (EDR):** Deploy modern EDR solutions with behavioral monitoring to detect and isolate suspicious process activity before lateral movement occurs.
5. **Air-Gapped & Immutable Backups:** Maintain offline, immutable backups of critical systems. Test backup restoration regularly so recovery does not depend on paying ransoms.
6. **Continuous Security Awareness Training:** Run realistic simulated phishing exercises so employees can spot modern social engineering tactics.

---

## 6. Conclusion

The modern cyber threat landscape is complex and constantly evolving, driven by automated tooling, organized RaaS groups, and expanded cloud infrastructure. Security can no longer rely on perimeter firewalls alone. Organizations must adopt an "assume breach" mindset, building layered defenses around identity protection, endpoint visibility, and rapid incident response to keep critical data safe.

---

## References
* MITRE ATT&CK Framework: Enterprise Matrix (`attack.mitre.org`)
* NIST Cybersecurity Framework 2.0 (NIST CSF)
* CISA Known Exploited Vulnerabilities (KEV) Catalog
* OWASP Top 10 Security Risks
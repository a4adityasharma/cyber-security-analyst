#!/usr/bin/env python3
"""
Nimbus Retail Solutions - Technical Policy Compliance Scanner
Author: Aditya
Task: Week 3 - Security Policy Review (supplementary technical artifact)

Purpose
-------
This script performs a LOCAL, READ-ONLY technical spot-check of a handful of the
controls discussed in the written Security Policy Review (Section 5 and Appendix B
of Security_Policy_Review.docx). It does not modify any system setting, does not
scan remote hosts, and does not require elevated privileges beyond what is needed
to read local configuration/status.

It is intended as a complementary, illustrative tool -- a way to show how a few of
the report's recommendations (password aging, firewall posture, disk encryption,
exposed legacy ports, centralized logging) could be checked programmatically on an
endpoint -- NOT as a replacement for the policy review itself.

Each check below is tagged with the report domain and control-framework mapping
it corresponds to, matching Appendix B of the written report:
    NIMBUS-IAM-01  -> Password & Authentication      (CIS Control 5/6, NIST 800-63B)
    NIMBUS-NET-02  -> Monitoring & Logging / Network  (CIS Control 8, 12)
    NIMBUS-END-03  -> Remote Work / BYOD (disk encryption) (CIS Control 4)

Usage:
    python3 nimbus_policy_compliance_scanner.py
    python3 nimbus_policy_compliance_scanner.py --json   # machine-readable output
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys


class ComplianceCheck:
    def __init__(self, control_id, domain, description):
        self.control_id = control_id
        self.domain = domain
        self.description = description
        self.status = "SKIPPED"
        self.detail = ""

    def to_dict(self):
        return {
            "control_id": self.control_id,
            "domain": self.domain,
            "description": self.description,
            "status": self.status,
            "detail": self.detail,
        }


class NimbusComplianceScanner:
    """
    Read-only local scanner. Every method fails soft: if a check cannot be
    performed (missing tool, insufficient permission, unsupported OS), the
    control is marked SKIPPED with an explanation rather than crashing or
    guessing at a result.
    """

    # Points deducted per FAIL, out of a 100-point starting score.
    PENALTY = {
        "NIMBUS-IAM-01": 20,   # weak/no password aging policy
        "NIMBUS-NET-02a": 15,  # host firewall inactive
        "NIMBUS-NET-02b": 15,  # legacy cleartext port exposed
        "NIMBUS-NET-02c": 10,  # no centralized log forwarding/daemon detected
        "NIMBUS-END-03": 15,   # disk encryption not detected
    }

    LEGACY_PORTS = {
        "21": "FTP (cleartext file transfer)",
        "23": "Telnet (cleartext remote shell)",
        "445": "SMB (frequently targeted for lateral movement)",
        "3389": "RDP (high-value target for credential attacks)",
        "5900": "VNC (often unauthenticated or weakly authenticated)",
    }

    def __init__(self):
        self.os_type = platform.system()
        self.checks = []
        self.score = 100

    def _run(self, cmd):
        """Run a command, return stdout as text, or None if it fails/missing."""
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, check=False
            )
            return out.stdout + out.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _record(self, control_id, domain, description, status, detail):
        c = ComplianceCheck(control_id, domain, description)
        c.status = status
        c.detail = detail
        self.checks.append(c)
        if status == "FAIL":
            self.score = max(0, self.score - self.PENALTY.get(control_id, 10))

    # ---- NIMBUS-IAM-01: Password & Authentication -------------------------
    def check_password_aging(self):
        cid, domain = "NIMBUS-IAM-01", "Password & Authentication (Report Sec. 5.1)"
        if self.os_type != "Linux":
            self._record(cid, domain, "Local password aging policy",
                          "SKIPPED", f"Not checked on {self.os_type}; on Windows this is "
                          "typically managed centrally via Group Policy / Entra ID and "
                          "should be reviewed there instead of on the local host.")
            return
        path = "/etc/login.defs"
        if not os.path.exists(path):
            self._record(cid, domain, "Local password aging policy", "SKIPPED",
                          f"{path} not found on this system.")
            return
        try:
            with open(path, "r") as f:
                content = f.read()
        except PermissionError:
            self._record(cid, domain, "Local password aging policy", "SKIPPED",
                          f"No permission to read {path}.")
            return

        min_len_ok = any(
            line.split()[0] == "PASS_MIN_LEN" and int(line.split()[1]) >= 12
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#") and line.split()[0] == "PASS_MIN_LEN"
        ) if "PASS_MIN_LEN" in content else False

        if min_len_ok:
            self._record(cid, domain, "Local password aging policy", "PASS",
                         "PASS_MIN_LEN >= 12 found in login.defs, consistent with the "
                         "report's recommended 12-character minimum.")
        else:
            self._record(cid, domain, "Local password aging policy", "FAIL",
                         "login.defs does not enforce a minimum length of 12+ characters. "
                         "This matches the gap described in Report Section 5.1 -- update "
                         "PASS_MIN_LEN (or the PAM/pwquality module, which supersedes "
                         "login.defs on modern distros) to require 12+ characters.")

    # ---- NIMBUS-NET-02a: Host firewall -------------------------------------
    def check_firewall(self):
        cid, domain = "NIMBUS-NET-02a", "Monitoring & Network Exposure (Report Sec. 5.8)"
        if self.os_type == "Linux":
            if shutil.which("ufw"):
                out = self._run(["ufw", "status"])
                if out and "active" in out.lower():
                    self._record(cid, domain, "Host firewall status", "PASS", "UFW is active.")
                    return
                elif out is not None:
                    self._record(cid, domain, "Host firewall status", "FAIL",
                                 "UFW is installed but not active.")
                    return
            if shutil.which("firewall-cmd"):
                out = self._run(["firewall-cmd", "--state"])
                if out and "running" in out.lower():
                    self._record(cid, domain, "Host firewall status", "PASS", "firewalld is running.")
                    return
                elif out is not None:
                    self._record(cid, domain, "Host firewall status", "FAIL", "firewalld is not running.")
                    return
            self._record(cid, domain, "Host firewall status", "SKIPPED",
                         "No supported firewall manager (ufw/firewalld) detected or accessible; "
                         "verify manually with `iptables -L` or your cloud provider's security groups.")
        elif self.os_type == "Windows":
            out = self._run(["netsh", "advfirewall", "show", "allprofiles", "state"])
            if out and out.upper().count("ON") >= 1 and "OFF" not in out.upper():
                self._record(cid, domain, "Host firewall status", "PASS", "Windows Firewall reports ON for all profiles.")
            elif out is not None:
                self._record(cid, domain, "Host firewall status", "FAIL",
                             "Windows Firewall is OFF for at least one profile.")
            else:
                self._record(cid, domain, "Host firewall status", "SKIPPED", "Could not query netsh.")
        else:
            self._record(cid, domain, "Host firewall status", "SKIPPED", f"Unsupported OS: {self.os_type}")

    # ---- NIMBUS-NET-02b: Legacy / cleartext ports --------------------------
    def check_legacy_ports(self):
        cid, domain = "NIMBUS-NET-02b", "Monitoring & Network Exposure (Report Sec. 5.8)"
        cmd = ["netstat", "-tuln"] if self.os_type != "Windows" else ["netstat", "-ano"]
        out = self._run(cmd)
        if out is None and self.os_type != "Windows":
            # netstat may be absent on modern minimal distros; fall back to ss
            out = self._run(["ss", "-tuln"])
        if out is None:
            self._record(cid, domain, "Legacy/cleartext listening ports", "SKIPPED",
                         "Neither netstat nor ss is available on this system.")
            return

        found = [f"{port} ({name})" for port, name in self.LEGACY_PORTS.items() if f":{port} " in out or f":{port}\t" in out]
        if found:
            self._record(cid, domain, "Legacy/cleartext listening ports", "FAIL",
                         "Listening on legacy/high-risk port(s): " + ", ".join(found) +
                         ". Report Section 5.8 recommends disabling cleartext management "
                         "protocols and restricting SMB/RDP/VNC to management VLANs only.")
        else:
            self._record(cid, domain, "Legacy/cleartext listening ports", "PASS",
                         "None of the commonly-exploited legacy ports (21/23/445/3389/5900) "
                         "were found listening.")

    # ---- NIMBUS-NET-02c: Centralized logging presence ----------------------
    def check_logging_daemon(self):
        cid, domain = "NIMBUS-NET-02c", "Monitoring & Logging (Report Sec. 5.8)"
        if self.os_type != "Linux":
            self._record(cid, domain, "Local logging/forwarding daemon", "SKIPPED",
                         f"Not checked on {self.os_type}; verify Windows Event Forwarding "
                         "or SIEM agent installation separately.")
            return
        candidates = ["rsyslog", "syslog-ng", "auditd", "journald"]
        out = self._run(["ps", "-e"])
        if out is None:
            self._record(cid, domain, "Local logging/forwarding daemon", "SKIPPED", "Could not list processes.")
            return
        running = [c for c in candidates if c in out]
        if running:
            self._record(cid, domain, "Local logging/forwarding daemon", "PASS",
                         f"Detected logging service(s): {', '.join(running)}. Note: this only "
                         "confirms local logging is running, not that logs are forwarded to a "
                         "central SIEM as recommended in Report Section 5.8.")
        else:
            self._record(cid, domain, "Local logging/forwarding daemon", "FAIL",
                         "No common logging daemon detected. Without local logging, forwarding "
                         "to a central SIEM (per the report's recommendation) is not possible.")

    # ---- NIMBUS-END-03: Disk encryption ------------------------------------
    def check_disk_encryption(self):
        cid, domain = "NIMBUS-END-03", "Remote Work / BYOD & Endpoint Protection (Report Sec. 5.5)"
        if self.os_type == "Linux":
            out = self._run(["lsblk", "-o", "NAME,TYPE"])
            if out is None:
                self._record(cid, domain, "Disk/volume encryption", "SKIPPED", "lsblk not available.")
                return
            if "crypt" in out.lower():
                self._record(cid, domain, "Disk/volume encryption", "PASS",
                             "At least one LUKS-encrypted volume detected via lsblk.")
            else:
                self._record(cid, domain, "Disk/volume encryption", "FAIL",
                             "No LUKS-encrypted volumes detected. Report Section 5.5 recommends "
                             "mandatory device-level encryption before any endpoint can access "
                             "Restricted-tier data.")
        elif self.os_type == "Windows":
            out = self._run(["manage-bde", "-status"])
            if out and "Protection On" in out:
                self._record(cid, domain, "Disk/volume encryption", "PASS", "BitLocker reports Protection On.")
            elif out is not None:
                self._record(cid, domain, "Disk/volume encryption", "FAIL", "BitLocker is not enabled/protecting this volume.")
            else:
                self._record(cid, domain, "Disk/volume encryption", "SKIPPED", "manage-bde not available or requires elevation.")
        elif self.os_type == "Darwin":
            out = self._run(["fdesetup", "status"])
            if out and "FileVault is On" in out:
                self._record(cid, domain, "Disk/volume encryption", "PASS", "FileVault is On.")
            elif out is not None:
                self._record(cid, domain, "Disk/volume encryption", "FAIL", "FileVault is Off.")
            else:
                self._record(cid, domain, "Disk/volume encryption", "SKIPPED", "fdesetup not available.")
        else:
            self._record(cid, domain, "Disk/volume encryption", "SKIPPED", f"Unsupported OS: {self.os_type}")

    def run_all(self):
        self.check_password_aging()
        self.check_firewall()
        self.check_legacy_ports()
        self.check_logging_daemon()
        self.check_disk_encryption()

    def render_text(self):
        lines = []
        lines.append("=" * 72)
        lines.append("NIMBUS RETAIL SOLUTIONS - TECHNICAL POLICY COMPLIANCE SPOT-CHECK")
        lines.append(f"Host: {platform.node()}  |  OS: {self.os_type}")
        lines.append("Supplementary to: Security_Policy_Review.docx (Section 5 / Appendix B)")
        lines.append("=" * 72)
        for c in self.checks:
            lines.append(f"[{c.status:8s}] {c.control_id:16s} {c.description}")
            lines.append(f"             {c.detail}")
        lines.append("-" * 72)
        lines.append(f"Illustrative technical compliance score: {self.score}/100")
        lines.append("(This score reflects only the 5 spot-checks above -- it is NOT a")
        lines.append(" substitute for the full maturity scorecard in Report Section 6,")
        lines.append(" which covers all 10 policy domains.)")
        lines.append("=" * 72)
        return "\n".join(lines)

    def render_json(self):
        return json.dumps({
            "host": platform.node(),
            "os": self.os_type,
            "checks": [c.to_dict() for c in self.checks],
            "illustrative_score": self.score,
        }, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Nimbus Retail Solutions technical policy spot-checker.")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of text.")
    args = parser.parse_args()

    scanner = NimbusComplianceScanner()
    scanner.run_all()

    print(scanner.render_json() if args.json else scanner.render_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())

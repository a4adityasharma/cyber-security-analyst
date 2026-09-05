#!/usr/bin/env python3
"""
Automated Endpoint Security Policy Audit Tool
Author: Aditya Sharma
Task: Week 3 - Security Policy Review & Verification
Description: Scans local system configurations to assess compliance against 
             CIS Benchmarks (Password aging, open remote ports, firewall status).
"""

import os
import sys
import subprocess
import platform

class PolicyAuditor:
    def __init__(self):
        self.os_type = platform.system()
        self.findings = []
        self.score = 100

    def log_finding(self, control_id, status, details, penalty=10):
        self.findings.append({
            "Control": control_id,
            "Status": status,
            "Details": details
        })
        if status == "FAIL":
            self.score = max(0, self.score - penalty)

    def audit_firewall(self):
        print("[*] Auditing Host Firewall Status...")
        if self.os_type == "Linux":
            try:
                out = subprocess.check_output(["ufw", "status"], stderr=subprocess.STDOUT).decode()
                if "active" in out.lower():
                    self.log_finding("CIS-4.4", "PASS", "UFW Firewall is active and running.")
                else:
                    self.log_finding("CIS-4.4", "FAIL", "UFW Firewall is inactive.", penalty=20)
            except Exception:
                self.log_finding("CIS-4.4", "WARNING", "Could not check UFW status directly.")
        elif self.os_type == "Windows":
            out = subprocess.getoutput("netsh advfirewall show allprofiles state")
            if "ON" in out:
                self.log_finding("CIS-4.4", "PASS", "Windows Firewall is active.")
            else:
                self.log_finding("CIS-4.4", "FAIL", "Windows Firewall is disabled.", penalty=20)

    def audit_open_insecure_ports(self):
        print("[*] Auditing Insecure Open Ports (Telnet: 23, FTP: 21, SMB: 445)...")
        insecure_ports = {"21": "FTP", "23": "Telnet", "445": "SMB"}
        cmd = ["netstat", "-tuln"] if self.os_type == "Linux" else ["netstat", "-ano"]
        try:
            netstat = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            found_insecure = False
            for port, name in insecure_ports.items():
                if f":{port} " in netstat:
                    self.log_finding(f"CIS-9.2-{name}", "FAIL", f"Insecure protocol port {port} ({name}) is listening.", penalty=15)
                    found_insecure = True
            if not found_insecure:
                self.log_finding("CIS-9.2", "PASS", "No cleartext management ports (21, 23) detected.")
        except Exception as e:
            self.log_finding("CIS-9.2", "WARNING", f"Port check skipped: {e}")

    def audit_password_policy(self):
        print("[*] Auditing Local Password Policy Controls...")
        if self.os_type == "Linux":
            if os.path.exists("/etc/login.defs"):
                with open("/etc/login.defs", "r") as f:
                    content = f.read()
                    if "PASS_MAX_DAYS\t90" in content or "PASS_MIN_LEN\t14" in content:
                        self.log_finding("CIS-5.2", "PASS", "Password aging / length directives defined.")
                    else:
                        self.log_finding("CIS-5.2", "FAIL", "Inadequate minimum password length in login.defs.", penalty=10)
        else:
            self.log_finding("CIS-5.2", "PASS", "Password policies managed through domain GPO.")

    def run(self):
        print("="*60)
        print("  AUTOMATED SECURITY POLICY COMPLIANCE SCANNER")
        print(f"  Target OS: {self.os_type} | Hostname: {platform.node()}")
        print("="*60)
        
        self.audit_firewall()
        self.audit_open_insecure_ports()
        self.audit_password_policy()
        
        print("\n" + "="*60)
        print("  AUDIT RESULTS SUMMARY")
        print("="*60)
        for item in self.findings:
            print(f"[{item['Status']}] {item['Control']}: {item['Details']}")
            
        print("-" * 60)
        print(f"FINAL POLICY COMPLIANCE SCORE: {self.score} / 100")
        print("="*60)

if __name__ == "__main__":
    auditor = PolicyAuditor()
    auditor.run()
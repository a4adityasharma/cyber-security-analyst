#!/usr/bin/env python3
"""
Automated Incident Response Triage Script
Author: Aditya Sharma
Purpose: Collects volatile system telemetry, active network connections,
         and running processes during the initial detection phase.
"""

import os
import platform
import subprocess
import datetime

def generate_triage_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"triage_report_{timestamp}.txt"
    
    print(f"[*] Starting triage collection... Output: {report_file}")
    
    with open(report_file, "w") as f:
        f.write(f"=== CSIRT INCIDENT TRIAGE REPORT ===\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Hostname: {platform.node()}\n")
        f.write(f"OS: {platform.system()} {platform.release()} ({platform.version()})\n")
        f.write("="*40 + "\n\n")
        
        # 1. Active Network Connections
        f.write("--- 1. ACTIVE NETWORK CONNECTIONS ---\n")
        try:
            netstat = subprocess.check_output(["netstat", "-tuln"], stderr=subprocess.STDOUT).decode()
            f.write(netstat + "\n")
        except Exception as e:
            f.write(f"Error gathering network info: {e}\n")
            
        # 2. Running Processes
        f.write("--- 2. CURRENT RUNNING PROCESSES (TOP 20) ---\n")
        try:
            if platform.system() == "Linux" or platform.system() == "Darwin":
                ps = subprocess.check_output(["ps", "aux", "--sort=-%cpu"], stderr=subprocess.STDOUT).decode()
                f.write("\n".join(ps.splitlines()[:21]) + "\n")
            elif platform.system() == "Windows":
                tasklist = subprocess.check_output(["tasklist"], stderr=subprocess.STDOUT).decode()
                f.write(tasklist + "\n")
        except Exception as e:
            f.write(f"Error gathering process info: {e}\n")

        # 3. Logged In Users
        f.write("--- 3. CURRENT LOGGED-IN USERS ---\n")
        try:
            if platform.system() != "Windows":
                who = subprocess.check_output(["who"], stderr=subprocess.STDOUT).decode()
                f.write(who + "\n")
        except Exception as e:
            f.write(f"Error gathering user info: {e}\n")

    print(f"[+] Triage collection finished successfully: {report_file}")

if __name__ == "__main__":
    generate_triage_report()
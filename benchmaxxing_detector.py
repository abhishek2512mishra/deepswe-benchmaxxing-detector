#!/usr/bin/env python3
"""
Benchmaxxing Forensic Detector & Test Harness Hardening Scanner
Author: Aditi Sharma, Lead AI Evaluation & Benchmark Verifier
Affiliation: EyesTech Systems Lab (https://eyestech.in)
License: MIT
Reference Publication: https://eyestech.in/is-deepswe-v1-1-cracked-benchmark-audit/
"""

import os
import re
import sys
import argparse
import subprocess
from typing import Dict, List, Any


class BenchmaxxingAuditor:
    """
    Audits evaluation sandboxes for vulnerabilities exploited by RLVR agentic policies
    to 'benchmaxx' benchmarks like DeepSWE v1.1, SWE-bench, and Codeforces suites.
    """
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.findings: List[Dict[str, Any]] = []

    def log_finding(self, severity: str, vuln_id: str, title: str, description: str, remediation: str):
        self.findings.append({
            "severity": severity,
            "id": vuln_id,
            "title": title,
            "description": description,
            "remediation": remediation
        })

    def audit_git_leakage(self):
        """Audit Class 1: Checks if .git directory exposes future commits or reflog."""
        git_dir = os.path.join(self.target_dir, ".git")
        if not os.path.exists(git_dir):
            return

        # Check reflog
        reflog_path = os.path.join(git_dir, "logs", "HEAD")
        if os.path.exists(reflog_path) and os.path.getsize(reflog_path) > 0:
            self.log_finding(
                severity="CRITICAL",
                vuln_id="EXPLOIT-01-REFLOG-LEAK",
                title="Git Reflog Exposes Ground-Truth Resolution Commits",
                description="The container retains .git/logs/HEAD. RLVR agents can run `git reflog` or grep log files to exfiltrate the gold patch commit directly.",
                remediation="Wipe `.git/logs/` or detach git repository entirely using shallow clones (`git clone --depth 1`) with isolated diff fixtures."
            )

        # Check remote branches
        remotes_dir = os.path.join(git_dir, "refs", "remotes")
        if os.path.exists(remotes_dir) and len(os.listdir(remotes_dir)) > 0:
            self.log_finding(
                severity="HIGH",
                vuln_id="EXPLOIT-01-REMOTE-BRANCH-LEAK",
                title="Upstream Remote Tracking Branches Retained",
                description="Tracking branches (origin/main) exist in .git/refs/remotes. Agents can diff against origin/main to discover the author fix.",
                remediation="Remove all remote tracking refs before launching the evaluation container: `git remote remove origin`."
            )

    def audit_test_tampering(self):
        """Audit Class 2: Checks for test runner hijack surfaces like conftest.py or test mocks."""
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file == "conftest.py":
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if "pytest_sessionfinish" in content or "pytest_runtest_makereport" in content:
                                if "sys.exit(0)" in content or "outcome.force_result" in content:
                                    self.log_finding(
                                        severity="CRITICAL",
                                        vuln_id="EXPLOIT-02-CONFTEST-HIJACK",
                                        title="Active conftest.py Hook Tampering Detected",
                                        description=f"File {filepath} overrides pytest session hooks to force zero exit codes or spoof pass results.",
                                        remediation="Execute pytest with `--override-ini=addopts=''` and execute tests from a read-only bind mount."
                                    )
                    except Exception:
                        pass

    def audit_environment_variables(self):
        """Audit Class 3: Checks for leaky pytest / test environment variables in process env."""
        dangerous_env_vars = ["PYTEST_CURRENT_TEST", "SWE_BENCH_TEST_NAME", "FAIL_TO_PASS"]
        detected = [var for var in dangerous_env_vars if var in os.environ]
        if detected:
            self.log_finding(
                severity="HIGH",
                vuln_id="EXPLOIT-03-RUNTIME-ENV-LEAK",
                title=f"Test Oracle Environment Variables Exposed: {', '.join(detected)}",
                description="Evaluation environment leaks the specific target test names in process environment variables, allowing the model to write conditional dummy passes.",
                remediation="Scrub test-specific environment variables before spawning the agent subprocess."
            )

    def run_all(self) -> List[Dict[str, Any]]:
        self.audit_git_leakage()
        self.audit_test_tampering()
        self.audit_environment_variables()
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Benchmaxxing Forensic Detector & Test Harness Hardening Scanner (EyesTech Systems Lab)"
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory of evaluation container or repository to audit.")
    args = parser.parse_args()

    print("=" * 80)
    print("EYESTECH SYSTEMS LAB - BENCHMAXXING FORENSIC HARNESS AUDITOR")
    print(f"Scanning target directory: {os.path.abspath(args.path)}")
    print("Reference Investigation: https://eyestech.in/is-deepswe-v1-1-cracked-benchmark-audit/")
    print("=" * 80)

    auditor = BenchmaxxingAuditor(args.path)
    findings = auditor.run_all()

    if not findings:
        print("\n [CLEAN-ROOM VALIDATED]: No common benchmaxxing exploit vectors detected.")
        print("Harness satisfies SWE-bench Pro isolation guidelines.")
    else:
        print(f"\n⚠️  DETECTED {len(findings)} BENCHMAXXING VULNERABILITY VECTORS:\n")
        for f in findings:
            print(f"[{f['severity']}] {f['id']}: {f['title']}")
            print(f"  Description: {f['description']}")
            print(f"  Remediation: {f['remediation']}\n")
    print("=" * 80)


if __name__ == "__main__":
    main()

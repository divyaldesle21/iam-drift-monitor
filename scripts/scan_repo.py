import os
import sys
import re
import glob

DANGEROUS_PATTERNS = {
    "hardcoded_aws_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "reason": "Hardcoded AWS Access Key ID found in source code",
        "mitre": "T1552.001 - Credentials in Files"
    },
    "hardcoded_secret": {
        "pattern": r"(?i)(aws_secret_access_key|secret_key|secretkey)\s*[=:]\s*['\"][A-Za-z0-9/+=]{20,}['\"]",
        "severity": "CRITICAL",
        "reason": "Hardcoded AWS Secret Key found in source code",
        "mitre": "T1552.001 - Credentials in Files"
    },
    "iam_passrole": {
        "pattern": r"iam:PassRole",
        "severity": "HIGH",
        "reason": "iam:PassRole privilege escalation action in code",
        "mitre": "T1548 - Abuse Elevation Control"
    },
    "wildcard_action": {
        "pattern": r'"Action"\s*:\s*"\*"',
        "severity": "CRITICAL",
        "reason": "Wildcard IAM action grants full admin access",
        "mitre": "T1078 - Valid Accounts"
    },
    "wildcard_resource": {
        "pattern": r'"Resource"\s*:\s*"\*"',
        "severity": "HIGH",
        "reason": "Wildcard Resource allows action on all AWS resources",
        "mitre": "T1078 - Valid Accounts"
    },
    "insecure_ssl": {
        "pattern": r"(?i)(verify\s*=\s*False|ssl_verify\s*=\s*False|InsecureRequestWarning)",
        "severity": "HIGH",
        "reason": "SSL verification disabled - vulnerable to MITM attacks",
        "mitre": "T1557 - Adversary in the Middle"
    },
    "hardcoded_password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "severity": "HIGH",
        "reason": "Hardcoded password found in source code",
        "mitre": "T1552.001 - Credentials in Files"
    },
    "aws_account_id": {
        "pattern": r"\b[0-9]{12}\b",
        "severity": "MEDIUM",
        "reason": "Hardcoded AWS Account ID exposes account information",
        "mitre": "T1589 - Gather Victim Identity Information"
    },
    "debug_enabled": {
        "pattern": r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)",
        "severity": "MEDIUM",
        "reason": "Debug mode enabled - exposes sensitive information",
        "mitre": "T1082 - System Information Discovery"
    },
    "shell_injection": {
        "pattern": r"(?i)(os\.system|subprocess\.call|eval\(|exec\()",
        "severity": "HIGH",
        "reason": "Potential shell injection or code execution vulnerability",
        "mitre": "T1059 - Command and Scripting Interpreter"
    },
    "s3_public_acl": {
        "pattern": r"(?i)(public-read|public-read-write|authenticated-read)",
        "severity": "HIGH",
        "reason": "S3 bucket ACL set to public - data exposure risk",
        "mitre": "T1530 - Data from Cloud Storage"
    },
    "assume_role": {
        "pattern": r"sts\.assume_role|sts:AssumeRole",
        "severity": "MEDIUM",
        "reason": "Role assumption in code - verify least privilege",
        "mitre": "T1550 - Use Alternate Authentication"
    }
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".terraform",
             "vendor", "dist", "build", ".idea", "venv"}

SCAN_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".go", ".rb", ".php",
    ".tf", ".yaml", ".yml", ".json", ".xml", ".properties",
    ".env", ".config", ".conf", ".sh", ".bash", ".ps1"
}

def find_files(repo_path):
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SCAN_EXTENSIONS or filename in {".env", "Dockerfile", "Makefile"}:
                files.append(os.path.join(root, filename))
    return files

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
        for pattern_name, details in DANGEROUS_PATTERNS.items():
            matches = list(re.finditer(details["pattern"], content, re.MULTILINE))
            for match in matches:
                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num-1].strip()[:100] if line_num <= len(lines) else ""
                findings.append({
                    "pattern": pattern_name,
                    "severity": details["severity"],
                    "reason": details["reason"],
                    "mitre": details["mitre"],
                    "file": filepath,
                    "line": line_num,
                    "content": line_content
                })
    except Exception:
        pass
    return findings

def scan_repository(repo_path):
    print(f"\nScanning repository: {repo_path}")
    print("="*60)
    files = find_files(repo_path)
    print(f"Files found        : {len(files)}")
    print(f"Patterns checked   : {len(DANGEROUS_PATTERNS)}")
    print(f"Scanning...\n")
    all_findings = []
    files_with_issues = set()
    for filepath in files:
        findings = scan_file(filepath)
        if findings:
            files_with_issues.add(filepath)
            all_findings.extend(findings)
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["severity"] == "HIGH"]
    medium   = [f for f in all_findings if f["severity"] == "MEDIUM"]
    print(f"FILES WITH ISSUES: {len(files_with_issues)}")
    print(f"TOTAL FINDINGS   : {len(all_findings)}")
    print(f"CRITICAL         : {len(critical)}")
    print(f"HIGH             : {len(high)}")
    print(f"MEDIUM           : {len(medium)}")
    if all_findings:
        print(f"\nTOP FINDINGS:")
        print("-"*60)
        shown = set()
        for f in sorted(all_findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}[x["severity"]]):
            key = f"{f['pattern']}:{os.path.basename(f['file'])}"
            if key in shown: continue
            shown.add(key)
            icon = "CRITICAL" if f["severity"] == "CRITICAL" else "HIGH" if f["severity"] == "HIGH" else "MEDIUM"
            rel_path = os.path.relpath(f["file"], repo_path)
            print(f"\n  [{icon}] {f['reason']}")
            print(f"  File   : {rel_path}:{f['line']}")
            print(f"  MITRE  : {f['mitre']}")
            print(f"  Code   : {f['content']}")
            if len(shown) >= 15: break
    print("\n" + "="*60)
    if critical:
        print("VERDICT: CRITICAL security issues found in source code.")
    elif high:
        print("VERDICT: HIGH severity issues found. Review required.")
    elif medium:
        print("VERDICT: MEDIUM severity findings. Low risk.")
    else:
        print("VERDICT: No security issues detected.")
    print("="*60 + "\n")
    return all_findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    findings = scan_repository(repo_path)
    critical = any(f["severity"] == "CRITICAL" for f in findings)
    sys.exit(1 if critical else 0)
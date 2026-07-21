import os
import sys
import json
import re
import glob

def find_tf_files(repo_path):
    pattern = os.path.join(repo_path, "**", "*.tf")
    files = glob.glob(pattern, recursive=True)
    return [f for f in files if ".terraform" not in f]

def extract_iam_from_tf(filepath):
    """Parse .tf file and extract IAM policy blocks"""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Find aws_iam_policy_document blocks
        policy_blocks = re.findall(
            r'resource\s+"(aws_iam[^"]+)"\s+"([^"]+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content, re.DOTALL
        )

        # Find inline policy statements
        statements = re.findall(
            r'statement\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content, re.DOTALL
        )

        # Find action patterns directly
        action_patterns = re.findall(
            r'actions\s*=\s*\[([^\]]+)\]',
            content
        )
        not_actions = re.findall(
            r'not_actions\s*=\s*\[([^\]]+)\]',
            content
        )
        resources = re.findall(
            r'resources\s*=\s*\[([^\]]+)\]',
            content
        )

        # Check for dangerous patterns
        dangerous = {
            "wildcard_action":    r'"[*]"',
            "iam_passrole":       r'"iam:PassRole"',
            "s3_delete":          r'"s3:Delete(?:Bucket|Object|BucketPolicy)"',
            "iam_escalation":     r'"iam:(?:CreatePolicyVersion|AttachRolePolicy|PutRolePolicy|CreateRole)"',
            "full_admin":         r'"AdministratorAccess"',
            "cloudtrail_disable": r'"cloudtrail:(?:StopLogging|DeleteTrail)"',
            "iam_create_user":    r'"iam:CreateUser"',
            "iam_create_key":     r'"iam:CreateAccessKey"',
            "kms_decrypt":        r'"kms:Decrypt"',
            "secrets_access":     r'"secretsmanager:GetSecretValue"',
            "wildcard_resource":  r'resources\s*=\s*\[\s*"\*"\s*\]',
        }

        for pattern_name, pattern in dangerous.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "file": filepath,
                    "pattern": pattern_name,
                    "matches": matches,
                    "count": len(matches),
                    "severity": "HIGH" if pattern_name not in ["kms_decrypt", "secrets_access"] else "MEDIUM"
                })

    except Exception as e:
        pass

    return findings

def scan_repository(repo_path):
    print(f"\nScanning repository: {repo_path}")
    print("="*60)

    tf_files = find_tf_files(repo_path)
    print(f"Found {len(tf_files)} Terraform files\n")

    if not tf_files:
        print("No .tf files found in this directory")
        return []

    all_findings = []
    files_with_issues = 0

    for tf_file in tf_files:
        findings = extract_iam_from_tf(tf_file)
        if findings:
            files_with_issues += 1
            rel_path = os.path.relpath(tf_file, repo_path)
            print(f"\n{'='*50}")
            print(f"FILE: {rel_path}")
            print(f"{'='*50}")
            for f in findings:
                icon = "🚨" if f["severity"] == "HIGH" else "⚠️"
                print(f"{icon} [{f['severity']}] {f['pattern'].upper().replace('_', ' ')}")
                print(f"   Matches: {', '.join(set(str(m) for m in f['matches'][:3]))}")
            all_findings.extend(findings)

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Total .tf files scanned : {len(tf_files)}")
    print(f"Files with IAM issues   : {files_with_issues}")
    print(f"Total findings          : {len(all_findings)}")

    high = [f for f in all_findings if f["severity"] == "HIGH"]
    med  = [f for f in all_findings if f["severity"] == "MEDIUM"]
    print(f"HIGH severity           : {len(high)}")
    print(f"MEDIUM severity         : {len(med)}")

    if all_findings:
        print(f"\nTOP FINDINGS:")
        seen = set()
        for f in all_findings:
            key = f["pattern"]
            if key not in seen:
                seen.add(key)
                print(f"  • {f['pattern'].replace('_',' ').upper()} — found in {sum(1 for x in all_findings if x['pattern']==key)} file(s)")

    return all_findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    findings = scan_repository(repo_path)
    sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)
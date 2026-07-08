import os
import sys
import urllib.request
import urllib.parse
import json

def send_discord(findings, repo, actor, branch, run_url):
    webhook = os.environ.get("DISCORD_WEBHOOK")
    if not webhook:
        print("No DISCORD_WEBHOOK set, skipping alert.")
        return

    lines = [f"🚨 **IAM Drift Detected** in `{repo}`"]
    lines.append(f"**Branch:** `{branch}` | **Author:** `{actor}`")
    lines.append(f"**Run:** {run_url}\n")

    for f in findings:
        icon = "🔴" if f["severity"] == "HIGH" else "🟡"
        lines.append(f"{icon} `{f['resource']}` — {f['reason']}")

    payload = json.dumps({"content": "\n".join(lines)}).encode("utf-8")
    req = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        urllib.request.urlopen(req)
        print("Discord alert sent.")
    except Exception as e:
        print(f"Discord alert failed: {e}")

if __name__ == "__main__":
    sample_findings = [
        {"resource": "aws_iam_role_policy.bad_policy", "severity": "HIGH",
         "reason": "iam:PassRole with wildcard Resource"},
        {"resource": "aws_iam_role_policy.bad_policy", "severity": "HIGH",
         "reason": "Dangerous action 's3:DeleteBucket' with wildcard Resource"}
    ]
    send_discord(
        findings=sample_findings,
        repo="divyaldesle21/iam-drift-monitor",
        actor="divyaldesle21",
        branch="test/vulnerable-policy",
        run_url="https://github.com/divyaldesle21/iam-drift-monitor/actions"
    )
import json
import sys
import os

DANGEROUS_ACTIONS = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "s3:DeleteBucket",
    "s3:DeleteObject",
    "s3:DeleteBucketPolicy",
    "s3:*",              # ADD THIS
    "ec2:*",
    "lambda:*",
    "cloudwatch:*",      # ADD THIS
    "sts:AssumeRole",
    "dynamodb:DeleteTable",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
]
def parse_policy(policy_str):
    if isinstance(policy_str, dict):
        return policy_str
    try:
        return json.loads(policy_str)
    except Exception:
        return {}

def check_statement(stmt, resource_address):
    findings = []
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    effect = stmt.get("Effect", "")

    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]

    if effect != "Allow":
        return findings

    # wildcard action
    if "*" in actions:
        findings.append({
            "resource": resource_address,
            "severity": "HIGH",
            "reason": "Wildcard Action '*' grants full access"
        })

    # iam:PassRole + wildcard resource
    if "iam:PassRole" in actions and "*" in resources:
        findings.append({
            "resource": resource_address,
            "severity": "HIGH",
            "reason": "iam:PassRole with wildcard Resource — privilege escalation risk"
        })

    # dangerous actions with wildcard resource
    for action in actions:
        if action in DANGEROUS_ACTIONS and "*" in resources:
            if action != "iam:PassRole":  # already caught above
                findings.append({
                    "resource": resource_address,
                    "severity": "HIGH",
                    "reason": f"Dangerous action '{action}' with wildcard Resource"
                })

    # wildcard resource alone (medium)
    if "*" in resources and not any(f["severity"] == "HIGH" for f in findings):
        findings.append({
            "resource": resource_address,
            "severity": "MEDIUM",
            "reason": "Wildcard Resource '*' is overly permissive"
        })

    return findings

def scan_plan(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)

    all_findings = []

    for change in plan.get("resource_changes", []):
        resource_type = change.get("type", "")
        if "aws_iam" not in resource_type:
            continue

        actions = change.get("change", {}).get("actions", [])
        if not set(actions) & {"create", "update"}:
            continue

        after = change.get("change", {}).get("after") or {}
        policy_str = after.get("policy") or after.get("assume_role_policy")
        if not policy_str:
            continue

        policy = parse_policy(policy_str)
        for stmt in policy.get("Statement", []):
            findings = check_statement(stmt, change["address"])
            all_findings.extend(findings)

    return all_findings

def main():
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "plan.json"

    if not os.path.exists(plan_path):
        print(f"ERROR: plan file not found: {plan_path}")
        sys.exit(1)

    print(f"Scanning {plan_path}...\n")
    findings = scan_plan(plan_path)

    blocked = False
    if not findings:
        print("✓ No per-statement IAM privilege drift detected.\n")
    else:
        print(f"Found {len(findings)} finding(s):\n")
        for f in findings:
            icon = "🚨" if f["severity"] == "HIGH" else "⚠️"
            print(f"{icon} [{f['severity']}] {f['resource']}")
            print(f"   → {f['reason']}\n")
            if f["severity"] == "HIGH":
                blocked = True

# Graph-based attack path analysis
    try:
        from graph_engine import analyze_graph, print_graph_report
        _, graph_stats = analyze_graph(plan_path)
        graph_blocked = print_graph_report(graph_stats)
        if graph_blocked:
            blocked = True
    except Exception as e:
        print(f"Graph analysis skipped: {e}")

# OPA/Rego policy engine
    try:
        from opa_runner import analyze_opa, print_opa_report
        opa_violations = analyze_opa(plan_path)
        opa_blocked = print_opa_report(opa_violations)
        if opa_blocked:
            blocked = True
    except Exception as e:
        print(f"OPA analysis skipped: {e}")

# ML anomaly scoring
    try:
        from ml_scorer import analyze_ml, print_ml_report
        ml_results = analyze_ml(plan_path)
        ml_blocked = print_ml_report(ml_results)
        if ml_blocked:
            blocked = True
    except Exception as e:
        print(f"ML analysis skipped: {e}")

    if blocked:
        print("BUILD BLOCKED — HIGH severity findings detected.")
        sys.exit(1)
    else:
        print("BUILD PASSED — only MEDIUM findings, review recommended.")
        sys.exit(0)

if __name__ == "__main__":
    main()
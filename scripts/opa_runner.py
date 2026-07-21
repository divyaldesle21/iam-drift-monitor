import json
import subprocess
import os
import sys
import tempfile

POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "policies", "iam_rules.rego")

def normalize_statement(stmt):
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return {
        "Effect": stmt.get("Effect", "Allow"),
        "Action": actions,
        "Resource": resources
    }

def run_opa_on_statement(stmt):
    input_data = {"statement": normalize_statement(stmt)}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(input_data, f)
        input_path = f.name
    try:
        result = subprocess.run(
            ["opa", "eval",
             "--input", input_path,
             "--data", POLICY_PATH,
             "--format", "json",
             "data.iam.drift.violation"],
            capture_output=True,
            timeout=10
        )
        if result.returncode != 0:
            return []
        output = json.loads(result.stdout)
        violations = output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
        return violations if isinstance(violations, list) else []
    except Exception as e:
        print(f"OPA eval error: {e}")
        return []
    finally:
        os.unlink(input_path)

def analyze_opa(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)

    all_violations = []

    for change in plan.get("resource_changes", []):
        if "aws_iam" not in change.get("type", ""):
            continue
        actions = change.get("change", {}).get("actions", [])
        if not set(actions) & {"create", "update"}:
            continue
        after = change.get("change", {}).get("after") or {}
        policy_str = after.get("policy") or after.get("assume_role_policy")
        if not policy_str:
            continue
        try:
            policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        except Exception:
            continue

        for stmt in policy.get("Statement", []):
            violations = run_opa_on_statement(stmt)
            for v in violations:
                v["resource"] = change.get("address", "unknown")
                all_violations.append(v)

    return all_violations

def print_opa_report(violations):
    print("\n" + "="*50)
    print("OPA/REGO POLICY ENGINE")
    print("="*50)

    if not violations:
        print("✓ All OPA policy checks passed.")
        print("="*50 + "\n")
        return False

    blocked = False
    print(f"\n{len(violations)} policy violation(s):\n")

    for v in violations:
        sev = v.get("severity", "MEDIUM")
        icon = "💀" if sev == "CRITICAL" else "🚨" if sev == "HIGH" else "⚠️"
        print(f"  {icon} [{sev}] {v.get('rule_id', '???')} — {v.get('title', '')}")
        print(f"       Resource    : {v.get('resource', 'unknown')}")
        print(f"       MITRE ATT&CK: {v.get('mitre', 'N/A')}")
        print(f"       Remediation : {v.get('remediation', 'N/A')}")
        print()
        if sev in ("CRITICAL", "HIGH"):
            blocked = True

    print("="*50)
    if blocked:
        print("OPA VERDICT: Policy violations block deployment.")
    else:
        print("OPA VERDICT: No blocking violations found.")
    print("="*50 + "\n")
    return blocked

if __name__ == "__main__":
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    violations = analyze_opa(plan_path)
    blocked = print_opa_report(violations)
    sys.exit(1 if blocked else 0)
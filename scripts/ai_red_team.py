import json
import sys
import os
import urllib.request

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
API_URL = "https://api.anthropic.com/v1/messages"

def call_claude(prompt):
    if not ANTHROPIC_API_KEY:
        return "ERROR: ANTHROPIC_API_KEY not set"
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return f"API error {e.code}: {body}"
    except Exception as e:
        return f"Error: {e}"

def extract_permissions(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)
    permissions = set()
    resources = []
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
            if stmt.get("Effect") != "Allow":
                continue
            acts = stmt.get("Action", [])
            if isinstance(acts, str):
                acts = [acts]
            permissions.update(acts)
        resources.append(change.get("address", "unknown"))
    return permissions, resources

def run_red_team_agent(permissions, resources):
    prompt = f"""You are an expert AWS red team operator.
You have obtained IAM credentials with these permissions in a target AWS environment:

PERMISSIONS: {", ".join(sorted(permissions))}
TARGET RESOURCES: {", ".join(resources[:5])}

Simulate a realistic step by step attack chain using ONLY these permissions.
For each step include:
- STEP NUMBER and title
- PERMISSION USED
- EXACT AWS API CALL
- MITRE ATT&CK technique ID and name
- WHAT YOU GAINED
- NEXT MOVE

End with TOTAL DAMAGE ASSESSMENT and RISK RATING."""
    return call_claude(prompt)

def print_red_team_report(permissions, resources, narrative):
    print("\n" + "="*60)
    print("AUTONOMOUS AI RED TEAM AGENT")
    print("Powered by Claude AI  |  MITRE ATT&CK Aligned")
    print("="*60)
    print(f"\nPermissions analyzed : {len(permissions)}")
    print(f"Permissions          : {', '.join(sorted(permissions))}")
    print(f"Target resources     : {', '.join(resources[:3])}")
    print("\n" + "-"*60)
    print("ATTACK SIMULATION:")
    print("-"*60 + "\n")
    print(narrative)
    print("\n" + "="*60)
    print("END OF RED TEAM SIMULATION")
    print("="*60 + "\n")

def analyze_red_team(plan_path):
    permissions, resources = extract_permissions(plan_path)
    if not permissions:
        print("No IAM permissions found")
        return
    print("Running AI red team simulation... this takes 10-15 seconds")
    narrative = run_red_team_agent(permissions, resources)
    print_red_team_report(permissions, resources, narrative)

if __name__ == "__main__":
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "/app/plan.json"
    analyze_red_team(plan_path)
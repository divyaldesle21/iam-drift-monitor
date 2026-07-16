import json
import sys
import os
from datetime import datetime

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note"
}

def build_sarif(rule_findings, opa_findings, graph_stats):
    rules = {}

    # Rule-based findings
    for f in rule_findings:
        rule_id = f.get("rule_id", "IAM000")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("reason", "IAM Policy Violation"),
                "shortDescription": {"text": f.get("reason", "IAM Policy Violation")},
                "fullDescription": {"text": f.get("reason", "IAM Policy Violation")},
                "defaultConfiguration": {"level": SEVERITY_MAP.get(f.get("severity", "MEDIUM"), "warning")},
                "properties": {"tags": ["security", "iam", "aws"]}
            }

    # OPA findings
    for v in opa_findings:
        rule_id = v.get("rule_id", "OPA000")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": v.get("title", "OPA Policy Violation"),
                "shortDescription": {"text": v.get("title", "OPA Policy Violation")},
                "fullDescription": {"text": f"{v.get('title', '')} — MITRE ATT&CK: {v.get('mitre', 'N/A')}"},
                "help": {"text": v.get("remediation", "Review IAM permissions"), "markdown": f"**Remediation:** {v.get('remediation', 'Review IAM permissions')}"},
                "defaultConfiguration": {"level": SEVERITY_MAP.get(v.get("severity", "MEDIUM"), "warning")},
                "properties": {"tags": ["security", "iam", "opa", f"mitre:{v.get('mitre', 'N/A')}"]}
            }

    # Graph findings
    for path in graph_stats.get("attack_paths", []):
        rule_id = "GRAPH001"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": "Privilege Escalation Attack Path",
                "shortDescription": {"text": "Multi-hop privilege escalation path detected"},
                "fullDescription": {"text": "Graph analysis identified a privilege escalation chain across multiple IAM permissions — MITRE ATT&CK: T1548"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "iam", "graph", "mitre:T1548"]}
            }

    results = []

    for f in rule_findings:
        results.append({
            "ruleId": f.get("rule_id", "IAM000"),
            "level": SEVERITY_MAP.get(f.get("severity", "MEDIUM"), "warning"),
            "message": {"text": f"{f.get('reason', 'IAM violation')} on resource: {f.get('resource', 'unknown')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/main.tf", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1}}}],
            "properties": {"severity": f.get("severity"), "resource": f.get("resource")}
        })

    for v in opa_findings:
        results.append({
            "ruleId": v.get("rule_id", "OPA000"),
            "level": SEVERITY_MAP.get(v.get("severity", "MEDIUM"), "warning"),
            "message": {"text": f"{v.get('title', 'OPA violation')} — Remediation: {v.get('remediation', 'N/A')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/main.tf", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1}}}],
            "properties": {"severity": v.get("severity"), "mitre": v.get("mitre"), "resource": v.get("resource")}
        })

    for path in graph_stats.get("attack_paths", []):
        results.append({
            "ruleId": "GRAPH001",
            "level": SEVERITY_MAP.get(path.get("severity", "HIGH"), "error"),
            "message": {"text": path.get("description", "Attack path detected")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/main.tf", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1}}}],
            "properties": {"severity": path.get("severity"), "path_length": path.get("length")}
        })

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IAM-Drift-Monitor",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/divyaldesle21/iam-drift-monitor",
                    "rules": list(rules.values())
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }
    return sarif

def generate_sarif(plan_path, output_path="results.sarif"):
    sys.path.insert(0, os.path.dirname(__file__))
    from check_drift import scan_plan
    from opa_runner import analyze_opa
    from graph_engine import analyze_graph

    rule_findings = scan_plan(plan_path)
    opa_findings  = analyze_opa(plan_path)
    _, graph_stats = analyze_graph(plan_path)

    # Attach rule IDs to rule findings for SARIF
    for i, f in enumerate(rule_findings):
        f["rule_id"] = f"IAM{str(i+1).zfill(3)}"

    sarif = build_sarif(rule_findings, opa_findings, graph_stats)

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"SARIF report written to {output_path}")
    print(f"  {len(rule_findings)} rule findings")
    print(f"  {len(opa_findings)} OPA findings")
    print(f"  {len(graph_stats.get('attack_paths', []))} graph findings")
    print(f"  {len(sarif['runs'][0]['results'])} total results in SARIF")
    return output_path

if __name__ == "__main__":
    plan_path   = sys.argv[1] if len(sys.argv) > 1 else "/app/plan.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/app/results.sarif"
    generate_sarif(plan_path, output_path)
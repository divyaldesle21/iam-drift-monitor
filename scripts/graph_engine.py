import json
import networkx as nx

# Known privilege escalation chains based on MITRE ATT&CK T1548
ESCALATION_CHAINS = [
    # existing chains...
    ["lambda:CreateFunction", "iam:PassRole"],
    ["lambda:InvokeFunction", "lambda:CreateFunction"],
    ["iam:CreateRole", "iam:AttachRolePolicy"],
    ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
    ["sts:AssumeRole", "iam:AttachRolePolicy"],
    # ADD THESE for wildcard service detection
    ["lambda:*", "iam:PassRole"],        # lambda:* includes CreateFunction
    ["ec2:*", "iam:PassRole"],           # ec2:* includes RunInstances
    ["s3:*", "cloudtrail:StopLogging"],  # s3:* can exfiltrate then cover tracks
    ["lambda:*", "ec2:*"],              # serverless to compute pivot
    ["cloudwatch:*", "s3:*"],           # delete monitoring then exfiltrate
]

SENSITIVE_SERVICES = {
    "iam", "sts", "s3", "ec2", "lambda",
    "secretsmanager", "kms", "cloudtrail", "logs"
}

def build_permission_graph(findings_list):
    G = nx.DiGraph()
    all_actions = []

    for finding in findings_list:
        actions = finding.get("actions", [])
        resource = finding.get("resource", "unknown")
        for action in actions:
            G.add_node(action, resource=resource)
            all_actions.append(action)

    # Add edges where one permission enables another
    for chain in ESCALATION_CHAINS:
        for i in range(len(chain) - 1):
            src, dst = chain[i], chain[i+1]
            if src in all_actions and dst in all_actions:
                G.add_edge(src, dst, type="escalation_chain")

    return G

def find_attack_paths(G):
    paths = []
    nodes = list(G.nodes())

    for src in nodes:
        for dst in nodes:
            if src != dst:
                try:
                    all_paths = list(nx.all_simple_paths(G, src, dst, cutoff=3))
                    for path in all_paths:
                        if len(path) >= 2:
                            paths.append({
                                "path": path,
                                "length": len(path),
                                "severity": "CRITICAL" if len(path) >= 3 else "HIGH",
                                "description": f"Escalation path: {' → '.join(path)}"
                            })
                except nx.NetworkXNoPath:
                    pass

    return paths

def analyze_graph(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)

    findings_list = []
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
            actions_in_stmt = stmt.get("Action", [])
            if isinstance(actions_in_stmt, str):
                actions_in_stmt = [actions_in_stmt]
            findings_list.append({
                "resource": change.get("address", "unknown"),
                "actions": actions_in_stmt
            })

    G = build_permission_graph(findings_list)
    attack_paths = find_attack_paths(G)

    # Graph-level stats
    stats = {
        "total_permissions": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "sensitive_permissions": [
            n for n in G.nodes()
            if any(n.startswith(s + ":") for s in SENSITIVE_SERVICES)
        ],
        "attack_paths": attack_paths
    }

    return G, stats

def print_graph_report(stats):
    print("\n" + "="*50)
    print("GRAPH-BASED ATTACK PATH ANALYSIS")
    print("="*50)
    print(f"Total permissions modeled : {stats['total_permissions']}")
    print(f"Permission relationships  : {stats['total_edges']}")
    print(f"Sensitive permissions     : {len(stats['sensitive_permissions'])}")

    if stats['sensitive_permissions']:
        print(f"  → {', '.join(stats['sensitive_permissions'])}")

    if not stats['attack_paths']:
        print("\n✓ No privilege escalation paths detected.")
    else:
        print(f"\n🔴 {len(stats['attack_paths'])} escalation path(s) found:\n")
        for p in stats['attack_paths']:
            icon = "💀" if p['severity'] == "CRITICAL" else "🚨"
            print(f"  {icon} [{p['severity']}] {p['description']}")

    print("="*50 + "\n")
    return len(stats['attack_paths']) > 0

if __name__ == "__main__":
    import sys
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    _, stats = analyze_graph(plan_path)
    has_paths = print_graph_report(stats)
    sys.exit(1 if has_paths else 0)
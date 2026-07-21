import json
import sys
import os

CAPABILITY_MAP = {
    # Identity & Access
    "iam:PassRole":              {"capability": "role_hijacking",      "impact": "Assume any IAM role, inherit its permissions",          "severity": 10},
    "iam:CreateRole":            {"capability": "role_creation",       "impact": "Create new IAM roles with arbitrary permissions",        "severity": 9},
    "iam:AttachRolePolicy":      {"capability": "policy_attachment",   "impact": "Attach any managed policy to any role",                 "severity": 9},
    "iam:PutRolePolicy":         {"capability": "inline_policy",       "impact": "Inject inline policies into any role",                  "severity": 9},
    "iam:CreatePolicyVersion":   {"capability": "policy_replacement",  "impact": "Replace existing policies with malicious versions",     "severity": 9},
    "iam:CreateAccessKey":       {"capability": "credential_theft",    "impact": "Create persistent backdoor credentials for any user",   "severity": 10},
    "iam:UpdateLoginProfile":    {"capability": "password_reset",      "impact": "Reset any IAM user password",                          "severity": 8},
    "iam:CreateUser":            {"capability": "backdoor_user",       "impact": "Create persistent backdoor IAM users",                 "severity": 9},
    "iam:AddUserToGroup":        {"capability": "privilege_group",     "impact": "Add users to privileged groups",                       "severity": 8},

    # Compute
    "ec2:RunInstances":          {"capability": "compute_hijack",      "impact": "Launch EC2 instances for crypto mining or C2",          "severity": 7},
    "ec2:*":                     {"capability": "full_compute",        "impact": "Full EC2 control — launch, stop, modify, delete any instance", "severity": 9},
    "ec2:DescribeInstances":     {"capability": "recon_compute",       "impact": "Enumerate all EC2 instances and metadata",              "severity": 3},
    "ec2:GetPasswordData":       {"capability": "windows_credential",  "impact": "Decrypt Windows administrator passwords",               "severity": 8},
    "ec2:ImportKeyPair":         {"capability": "ssh_backdoor",        "impact": "Import attacker SSH key for persistent EC2 access",    "severity": 7},

    # Serverless
    "lambda:CreateFunction":     {"capability": "serverless_exec",     "impact": "Deploy arbitrary code in Lambda environment",           "severity": 8},
    "lambda:InvokeFunction":     {"capability": "code_execution",      "impact": "Execute arbitrary Lambda functions",                    "severity": 7},
    "lambda:*":                  {"capability": "full_serverless",     "impact": "Full Lambda control — deploy, invoke, modify any function", "severity": 9},

    # Data
    "s3:GetObject":              {"capability": "data_read",           "impact": "Read any S3 object — credentials, backups, PII",       "severity": 6},
    "s3:ListBucket":             {"capability": "data_enum",           "impact": "Enumerate all S3 bucket contents",                     "severity": 4},
    "s3:PutObject":              {"capability": "data_write",          "impact": "Write/overwrite S3 objects — inject malicious content", "severity": 6},
    "s3:DeleteBucket":           {"capability": "data_destruction",    "impact": "Permanently delete S3 buckets and all contents",       "severity": 9},
    "s3:DeleteObject":           {"capability": "data_deletion",       "impact": "Delete individual S3 objects",                         "severity": 7},
    "s3:*":                      {"capability": "full_s3",             "impact": "Full S3 control — read, write, delete any bucket or object across entire account", "severity": 9},

    # Credential access
    "secretsmanager:GetSecretValue": {"capability": "secret_theft",   "impact": "Exfiltrate API keys, DB passwords, certificates",      "severity": 9},
    "kms:Decrypt":               {"capability": "decrypt_data",        "impact": "Decrypt any KMS-encrypted data at rest",               "severity": 8},
    "ssm:GetParameter":          {"capability": "param_theft",         "impact": "Read SSM parameters — often contains credentials",     "severity": 7},

    # Defense evasion
    "cloudtrail:StopLogging":    {"capability": "audit_evasion",       "impact": "Disable CloudTrail — removes all audit evidence",      "severity": 10},
    "cloudtrail:DeleteTrail":    {"capability": "audit_destruction",   "impact": "Permanently delete audit trail",                       "severity": 10},
    "cloudwatch:DeleteAlarms":   {"capability": "alert_evasion",       "impact": "Delete security alarms to avoid detection",            "severity": 8},
    "cloudwatch:*":              {"capability": "full_monitoring",     "impact": "Full CloudWatch control — delete all alarms, logs, dashboards and monitoring", "severity": 8},
    "guardduty:DeleteDetector":  {"capability": "ids_evasion",         "impact": "Disable GuardDuty threat detection",                   "severity": 10},
    "config:DeleteConfigRule":   {"capability": "compliance_evasion",  "impact": "Delete AWS Config compliance rules",                   "severity": 8},

    # Lateral movement
    "sts:AssumeRole":            {"capability": "lateral_movement",    "impact": "Move laterally by assuming roles in other accounts",   "severity": 8},
    "sts:GetFederationToken":    {"capability": "federation_abuse",    "impact": "Generate federated credentials for persistent access", "severity": 8},
}

ATTACK_CHAINS = [
    {
        "name": "Full Account Takeover",
        "required": ["iam:PassRole", "sts:AssumeRole"],
        "description": "Assume admin role via PassRole chain — full account control",
        "mitre": "T1548.005",
        "severity": "CRITICAL"
    },
    {
        "name": "Serverless Admin Backdoor",
        "required": ["lambda:*", "iam:PassRole"],
        "description": "Create Lambda with admin execution role — arbitrary code with admin permissions",
        "mitre": "T1648",
        "severity": "CRITICAL"
    },
    {
        "name": "Serverless Admin Backdoor (variant)",
        "required": ["lambda:CreateFunction", "iam:PassRole"],
        "description": "Deploy Lambda function with privileged IAM role attached",
        "mitre": "T1648",
        "severity": "CRITICAL"
    },
    {
        "name": "Full Data Exfiltration",
        "required": ["s3:*"],
        "description": "Read, copy, and delete all S3 data across the entire account",
        "mitre": "T1530",
        "severity": "CRITICAL"
    },
    {
        "name": "Compute Infrastructure Takeover",
        "required": ["ec2:*"],
        "description": "Launch crypto miners, install C2, modify security groups, terminate production instances",
        "mitre": "T1578",
        "severity": "CRITICAL"
    },
    {
        "name": "Audit Trail Destruction",
        "required": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
        "description": "Stop logging then delete trail — operate completely undetected",
        "mitre": "T1562.008",
        "severity": "CRITICAL"
    },
    {
        "name": "Monitoring Blind Spot",
        "required": ["cloudwatch:*"],
        "description": "Delete all CloudWatch alarms, logs, and dashboards — security team goes blind",
        "mitre": "T1562",
        "severity": "HIGH"
    },
    {
        "name": "Backdoor Credential Creation",
        "required": ["iam:CreateUser", "iam:CreateAccessKey"],
        "description": "Create hidden IAM user with persistent API access keys",
        "mitre": "T1136.003",
        "severity": "CRITICAL"
    },
    {
        "name": "Serverless Code Injection",
        "required": ["lambda:*", "ec2:*"],
        "description": "Deploy Lambda to pivot into EC2 — serverless to compute lateral movement",
        "mitre": "T1648",
        "severity": "HIGH"
    },
    {
        "name": "Exfiltrate Then Cover Tracks",
        "required": ["s3:*", "cloudwatch:*"],
        "description": "Exfiltrate all S3 data then delete CloudWatch logs to remove evidence",
        "mitre": "T1530,T1562",
        "severity": "CRITICAL"
    },
    {
        "name": "Policy Backdoor Injection",
        "required": ["iam:CreatePolicyVersion", "iam:AttachRolePolicy"],
        "description": "Replace existing policies with malicious versions — persistent escalation",
        "mitre": "T1548",
        "severity": "CRITICAL"
    },
    {
        "name": "Crypto Mining Infrastructure",
        "required": ["ec2:RunInstances"],
        "description": "Launch GPU instances for cryptocurrency mining at victim cost",
        "mitre": "T1496",
        "severity": "HIGH"
    },
    {
        "name": "Cross-Account Lateral Movement",
        "required": ["sts:AssumeRole", "iam:PassRole"],
        "description": "Chain role assumptions to move across AWS accounts",
        "mitre": "T1550.001",
        "severity": "CRITICAL"
    },
]

def extract_permissions(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)

    all_permissions = set()
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
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            all_permissions.update(stmt_actions)

    return all_permissions

def simulate_blast_radius(permissions):
    capabilities = []
    total_severity = 0
    highest_severity = 0

    for perm in permissions:
        if perm in CAPABILITY_MAP:
            cap = CAPABILITY_MAP[perm].copy()
            cap["permission"] = perm
            capabilities.append(cap)
            total_severity += cap["severity"]
            highest_severity = max(highest_severity, cap["severity"])

    active_chains = []
    for chain in ATTACK_CHAINS:
        if all(req in permissions for req in chain["required"]):
            active_chains.append(chain)

    blast_score = min(100, (total_severity * 3) + (len(active_chains) * 10))

    categories = {
        "account_takeover":  [c for c in capabilities if "role" in c["capability"] or "lateral" in c["capability"]],
        "data_exfiltration": [c for c in capabilities if "data" in c["capability"] or "secret" in c["capability"] or "decrypt" in c["capability"] or "s3" in c["capability"]],
        "defense_evasion":   [c for c in capabilities if "evasion" in c["capability"] or "destruction" in c["capability"] or "monitoring" in c["capability"]],
        "persistence":       [c for c in capabilities if "backdoor" in c["capability"] or "creation" in c["capability"]],
        "execution":         [c for c in capabilities if "exec" in c["capability"] or "compute" in c["capability"] or "serverless" in c["capability"] or "code" in c["capability"]],
    }

    return {
        "permissions_analyzed": list(permissions),
        "capabilities": capabilities,
        "attack_chains": active_chains,
        "categories": categories,
        "blast_score": blast_score,
        "total_severity": total_severity,
        "highest_severity": highest_severity
    }

def print_blast_report(result):
    score = result["blast_score"]
    chains = result["attack_chains"]
    caps = result["capabilities"]
    cats = result["categories"]

    if score >= 80:
        level = "CATASTROPHIC"
        label = "Full account compromise likely"
    elif score >= 60:
        level = "CRITICAL"
        label = "Severe damage possible"
    elif score >= 40:
        level = "HIGH"
        label = "Significant damage possible"
    elif score >= 20:
        level = "MEDIUM"
        label = "Limited damage possible"
    else:
        level = "LOW"
        label = "Minimal blast radius"

    bar_filled = score // 5
    bar = "X" * bar_filled + "." * (20 - bar_filled)

    print("\n" + "="*60)
    print("BLAST RADIUS SIMULATION")
    print("="*60)
    print(f"\nBlast Score  : [{bar}] {score}/100")
    print(f"Threat Level : {level} -- {label}")
    print(f"Permissions  : {len(result['permissions_analyzed'])} analyzed")
    print(f"Capabilities : {len(caps)} attack capabilities unlocked")
    print(f"Attack Chains: {len(chains)} multi-step attacks possible")

    if cats["account_takeover"]:
        print(f"\n[ACCOUNT TAKEOVER VECTORS ({len(cats['account_takeover'])}):]")
        for c in cats["account_takeover"]:
            print(f"   [{c['permission']}] --> {c['impact']}")

    if cats["data_exfiltration"]:
        print(f"\n[DATA EXFILTRATION VECTORS ({len(cats['data_exfiltration'])}):]")
        for c in cats["data_exfiltration"]:
            print(f"   [{c['permission']}] --> {c['impact']}")

    if cats["defense_evasion"]:
        print(f"\n[DEFENSE EVASION VECTORS ({len(cats['defense_evasion'])}):]")
        for c in cats["defense_evasion"]:
            print(f"   [{c['permission']}] --> {c['impact']}")

    if cats["persistence"]:
        print(f"\n[PERSISTENCE VECTORS ({len(cats['persistence'])}):]")
        for c in cats["persistence"]:
            print(f"   [{c['permission']}] --> {c['impact']}")

    if cats["execution"]:
        print(f"\n[CODE EXECUTION VECTORS ({len(cats['execution'])}):]")
        for c in cats["execution"]:
            print(f"   [{c['permission']}] --> {c['impact']}")

    if chains:
        print(f"\n[ACTIVE ATTACK CHAINS ({len(chains)}):]")
        for chain in chains:
            icon = "CRITICAL" if chain["severity"] == "CRITICAL" else "HIGH"
            print(f"\n   [{icon}] {chain['name']}")
            print(f"       Attack  : {chain['description']}")
            print(f"       MITRE   : {chain['mitre']}")
            print(f"       Requires: {' + '.join(chain['required'])}")
    else:
        print("\n[OK] No multi-step attack chains detected.")

    print("\n" + "="*60)
    print(f"BLAST RADIUS VERDICT: {level}")
    if score >= 40:
        print("An attacker with these permissions could achieve")
        print("significant damage or full account compromise.")
    print("="*60 + "\n")

    return score >= 40

if __name__ == "__main__":
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "/app/plan.json"
    permissions = extract_permissions(plan_path)
    result = simulate_blast_radius(permissions)
    blocked = print_blast_report(result)
    sys.exit(1 if blocked else 0)
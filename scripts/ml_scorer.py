import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

SENSITIVE_SERVICES = {
    "iam", "sts", "s3", "ec2", "lambda",
    "secretsmanager", "kms", "cloudtrail", "logs"
}

DANGEROUS_ACTIONS = {
    "iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy",
    "iam:PutRolePolicy", "iam:CreatePolicyVersion",
    "s3:DeleteBucket", "ec2:*", "lambda:*",
    "sts:AssumeRole", "kms:Decrypt", "secretsmanager:GetSecretValue"
}

# -------------------------------------------------------
# Training corpus — known-good IAM policies (safe baseline)
# These represent typical least-privilege patterns
# -------------------------------------------------------
SAFE_POLICIES = [
    {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::my-bucket/*"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["ec2:DescribeInstances", "ec2:DescribeTags"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["logs:CreateLogGroup", "logs:PutLogEvents"], "resources": ["arn:aws:logs:*"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "resources": ["arn:aws:s3:::app-bucket"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["lambda:InvokeFunction"], "resources": ["arn:aws:lambda:us-east-1:123:function:my-func"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["dynamodb:GetItem", "dynamodb:PutItem"], "resources": ["arn:aws:dynamodb:*:*:table/my-table"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["cloudwatch:PutMetricData"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["sqs:SendMessage", "sqs:ReceiveMessage"], "resources": ["arn:aws:sqs:us-east-1:123:my-queue"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["sns:Publish"], "resources": ["arn:aws:sns:us-east-1:123:my-topic"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["ecs:DescribeTasks", "ecs:ListTasks"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["secretsmanager:GetSecretValue"], "resources": ["arn:aws:secretsmanager:*:*:secret:my-secret"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["kms:Decrypt", "kms:GenerateDataKey"], "resources": ["arn:aws:kms:*:*:key/my-key"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["ssm:GetParameter"], "resources": ["arn:aws:ssm:*:*:parameter/my-param"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["route53:ChangeResourceRecordSets"], "resources": ["arn:aws:route53:::hostedzone/my-zone"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["cloudformation:DescribeStacks"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["sts:GetCallerIdentity"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["s3:ListAllMyBuckets"], "resources": ["*"], "wildcard_resources": 1, "wildcard_actions": 0},
    {"actions": ["codebuild:StartBuild", "codebuild:BatchGetBuilds"], "resources": ["arn:aws:codebuild:*:*:project/my-project"], "wildcard_resources": 0, "wildcard_actions": 0},
    {"actions": ["codecommit:GitPull"], "resources": ["arn:aws:codecommit:*:*:my-repo"], "wildcard_resources": 0, "wildcard_actions": 0},
]

def extract_features(actions, resources):
    """
    Convert a policy statement into a numeric feature vector.
    Features chosen to capture the statistical signature of privilege level.
    """
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]

    total_actions       = len(actions)
    wildcard_actions    = sum(1 for a in actions if "*" in a)
    sensitive_actions   = sum(1 for a in actions if any(a.startswith(s+":") for s in SENSITIVE_SERVICES))
    dangerous_actions   = sum(1 for a in actions if a in DANGEROUS_ACTIONS)
    wildcard_resources  = sum(1 for r in resources if r == "*")
    scoped_resources    = sum(1 for r in resources if r.startswith("arn:"))
    unique_services     = len({a.split(":")[0] for a in actions if ":" in a})
    has_passrole        = int("iam:PassRole" in actions)
    has_destructive     = int(any(a in ["s3:DeleteBucket", "ec2:TerminateInstances", "dynamodb:DeleteTable"] for a in actions))
    action_to_resource_ratio = total_actions / max(len(resources), 1)

    return [
        total_actions,
        wildcard_actions,
        sensitive_actions,
        dangerous_actions,
        wildcard_resources,
        scoped_resources,
        unique_services,
        has_passrole,
        has_destructive,
        action_to_resource_ratio
    ]

def build_training_data():
    X = []
    for policy in SAFE_POLICIES:
        features = extract_features(policy["actions"], policy["resources"])
        X.append(features)
    return np.array(X)

def train_model():
    X = build_training_data()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_scaled)
    return model, scaler

def score_policy(actions, resources, model, scaler):
    features = extract_features(actions, resources)
    X = np.array([features])
    X_scaled = scaler.transform(X)
    score = model.decision_function(X_scaled)[0]
    prediction = model.predict(X_scaled)[0]
    # Convert to 0-100 anomaly score (higher = more anomalous)
    anomaly_score = max(0, min(100, int((1 - score) * 50)))
    is_anomalous = prediction == -1
    return anomaly_score, is_anomalous, features

def analyze_ml(plan_path):
    with open(plan_path) as f:
        plan = json.load(f)

    model, scaler = train_model()
    results = []

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
            stmt_resources = stmt.get("Resource", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            if isinstance(stmt_resources, str):
                stmt_resources = [stmt_resources]

            anomaly_score, is_anomalous, features = score_policy(
                stmt_actions, stmt_resources, model, scaler
            )
            results.append({
                "resource": change.get("address", "unknown"),
                "actions": stmt_actions,
                "anomaly_score": anomaly_score,
                "is_anomalous": is_anomalous,
                "features": features
            })

    return results

def print_ml_report(results):
    print("\n" + "="*50)
    print("ML ANOMALY DETECTION (Isolation Forest)")
    print("="*50)

    if not results:
        print("No IAM statements to analyze.")
        print("="*50 + "\n")
        return False

    blocked = False
    for r in results:
        score = r["anomaly_score"]
        if score >= 70:
            level = "🔴 ANOMALOUS"
            blocked = True
        elif score >= 40:
            level = "🟡 SUSPICIOUS"
        else:
            level = "🟢 NORMAL"

        bar = "█" * (score // 10) + "░" * (10 - score // 10)
        print(f"\n  Resource : {r['resource']}")
        print(f"  Actions  : {', '.join(r['actions'][:3])}{'...' if len(r['actions']) > 3 else ''}")
        print(f"  Score    : [{bar}] {score}/100")
        print(f"  Status   : {level}")
        f = r["features"]
        print(f"  Features : {f[0]} actions, {f[2]} sensitive, {f[4]} wildcard resources, {f[6]} services")

    print("\n" + "="*50)
    if blocked:
        print("ML VERDICT: ANOMALOUS policies detected.")
    else:
        print("ML VERDICT: Policies within normal baseline.")
    print("="*50 + "\n")
    return blocked

if __name__ == "__main__":
    import sys
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    results = analyze_ml(plan_path)
    blocked = print_ml_report(results)
    sys.exit(1 if blocked else 0)
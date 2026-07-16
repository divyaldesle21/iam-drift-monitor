import json
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from check_drift import scan_plan, check_statement
from graph_engine import analyze_graph, find_attack_paths, build_permission_graph
from ml_scorer import analyze_ml, extract_features, train_model
from opa_runner import analyze_opa

import tempfile
import numpy as np

TEST_CORPUS = [
    {
        "id": "TP001", "label": True, "category": "privilege_escalation",
        "description": "iam:PassRole with wildcard — classic privilege escalation",
        "statement": {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": ["*"]}
    },
    {
        "id": "TP002", "label": True, "category": "full_admin",
        "description": "Full admin wildcard action",
        "statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
    },
    {
        "id": "TP003", "label": True, "category": "data_destruction",
        "description": "S3 DeleteBucket on wildcard",
        "statement": {"Effect": "Allow", "Action": ["s3:DeleteBucket"], "Resource": ["*"]}
    },
    {
        "id": "TP004", "label": True, "category": "privilege_escalation",
        "description": "iam:CreatePolicyVersion enables policy replacement",
        "statement": {"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": ["*"]}
    },
    {
        "id": "TP005", "label": True, "category": "compute_abuse",
        "description": "ec2:* wildcard on all resources",
        "statement": {"Effect": "Allow", "Action": ["ec2:*"], "Resource": ["*"]}
    },
    {
        "id": "TP006", "label": True, "category": "credential_access",
        "description": "SecretsManager on wildcard — credential harvesting",
        "statement": {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": ["*"]}
    },
    {
        "id": "TP007", "label": True, "category": "privilege_escalation",
        "description": "AttachRolePolicy enables attaching any policy to any role",
        "statement": {"Effect": "Allow", "Action": ["iam:AttachRolePolicy"], "Resource": ["*"]}
    },
    {
        "id": "TP008", "label": True, "category": "data_destruction",
        "description": "DynamoDB DeleteTable on wildcard",
        "statement": {"Effect": "Allow", "Action": ["dynamodb:DeleteTable", "dynamodb:DeleteItem"], "Resource": ["*"]}
    },
    {
        "id": "TP009", "label": True, "category": "lateral_movement",
        "description": "sts:AssumeRole on all resources",
        "statement": {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": ["*"]}
    },
    {
        "id": "TP010", "label": True, "category": "credential_access",
        "description": "KMS Decrypt on wildcard — can decrypt any data",
        "statement": {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": ["*"]}
    },
    {
        "id": "TP011", "label": True, "category": "privilege_escalation",
        "description": "Lambda CreateFunction + PassRole — can create privileged Lambda",
        "statement": {"Effect": "Allow", "Action": ["lambda:CreateFunction", "iam:PassRole"], "Resource": ["*"]}
    },
    {
        "id": "TP012", "label": True, "category": "defense_evasion",
        "description": "CloudTrail StopLogging — disables audit trail",
        "statement": {"Effect": "Allow", "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"], "Resource": ["*"]}
    },
    {
        "id": "TP013", "label": True, "category": "privilege_escalation",
        "description": "iam:PutRolePolicy on wildcard",
        "statement": {"Effect": "Allow", "Action": ["iam:PutRolePolicy"], "Resource": ["*"]}
    },
    {
        "id": "TP014", "label": True, "category": "data_destruction",
        "description": "S3 DeleteObject on all buckets",
        "statement": {"Effect": "Allow", "Action": ["s3:DeleteObject", "s3:DeleteBucketPolicy"], "Resource": ["*"]}
    },
    {
        "id": "TP015", "label": True, "category": "privilege_escalation",
        "description": "iam:CreateRole + iam:AttachRolePolicy — role creation chain",
        "statement": {"Effect": "Allow", "Action": ["iam:CreateRole", "iam:AttachRolePolicy"], "Resource": ["*"]}
    },
    # --- TRUE NEGATIVES (safe, should NOT be flagged) ---
    {
        "id": "TN001", "label": False, "category": "safe_read",
        "description": "S3 read-only scoped to specific bucket",
        "statement": {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::my-app-bucket/*"]}
    },
    {
        "id": "TN002", "label": False, "category": "safe_read",
        "description": "CloudWatch logs write scoped to log group",
        "statement": {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"], "Resource": ["arn:aws:logs:us-east-1:123:log-group:my-app"]}
    },
    {
        "id": "TN003", "label": False, "category": "safe_compute",
        "description": "EC2 describe only — read-only compute access",
        "statement": {"Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:DescribeTags"], "Resource": ["*"]}
    },
    {
        "id": "TN004", "label": False, "category": "safe_invoke",
        "description": "Lambda invoke scoped to specific function",
        "statement": {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": ["arn:aws:lambda:us-east-1:123:function:my-func"]}
    },
    {
        "id": "TN005", "label": False, "category": "safe_db",
        "description": "DynamoDB read/write on specific table",
        "statement": {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"], "Resource": ["arn:aws:dynamodb:us-east-1:123:table/my-table"]}
    },
    {
        "id": "TN006", "label": False, "category": "safe_deny",
        "description": "Deny effect — should always be ignored",
        "statement": {"Effect": "Deny", "Action": ["*"], "Resource": ["*"]}
    },
    {
        "id": "TN007", "label": False, "category": "safe_secrets",
        "description": "SecretsManager scoped to specific secret ARN",
        "statement": {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": ["arn:aws:secretsmanager:us-east-1:123:secret:my-app-secret"]}
    },
    {
        "id": "TN008", "label": False, "category": "safe_queue",
        "description": "SQS send/receive on specific queue",
        "statement": {"Effect": "Allow", "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"], "Resource": ["arn:aws:sqs:us-east-1:123:my-queue"]}
    },
    {
        "id": "TN009", "label": False, "category": "safe_kms",
        "description": "KMS scoped to specific key ARN",
        "statement": {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": ["arn:aws:kms:us-east-1:123:key/my-key-id"]}
    },
    {
        "id": "TN010", "label": False, "category": "safe_read",
        "description": "SSM parameter read scoped to path",
        "statement": {"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParameters"], "Resource": ["arn:aws:ssm:us-east-1:123:parameter/my-app/*"]}
    },
    {
        "id": "TN011", "label": False, "category": "safe_ecr",
        "description": "ECR image pull — read only",
        "statement": {"Effect": "Allow", "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": ["arn:aws:ecr:us-east-1:123:repository/my-repo"]}
    },
    {
        "id": "TN012", "label": False, "category": "safe_route53",
        "description": "Route53 record update scoped to zone",
        "statement": {"Effect": "Allow", "Action": ["route53:ChangeResourceRecordSets"], "Resource": ["arn:aws:route53:::hostedzone/Z123456"]}
    },
    {
        "id": "TN013", "label": False, "category": "safe_s3_write",
        "description": "S3 put scoped to deployment bucket",
        "statement": {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": ["arn:aws:s3:::deploy-bucket/*"]}
    },
    {
        "id": "TN014", "label": False, "category": "safe_monitoring",
        "description": "CloudWatch metrics write — monitoring only",
        "statement": {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData", "cloudwatch:GetMetricData"], "Resource": ["*"]}
    },
    {
        "id": "TN015", "label": False, "category": "safe_identity",
        "description": "sts:GetCallerIdentity — read only identity check",
        "statement": {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": ["*"]}
    },
]

def make_plan(statement):
    policy = {
        "Version": "2012-10-17",
        "Statement": [statement]
    }
    return {
        "resource_changes": [{
            "address": "aws_iam_role_policy.test_policy",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {"policy": json.dumps(policy)}
            }
        }]
    }

def evaluate_layer(layer_name, predict_fn):
    tp = fp = tn = fn = 0
    errors = []

    for case in TEST_CORPUS:
        try:
            predicted = predict_fn(case["statement"])
            actual = case["label"]

            if actual and predicted:
                tp += 1
            elif actual and not predicted:
                fn += 1
                errors.append(f"  MISSED [{case['id']}] {case['description']}")
            elif not actual and predicted:
                fp += 1
                errors.append(f"  FALSE+ [{case['id']}] {case['description']}")
            else:
                tn += 1
        except Exception as e:
            errors.append(f"  ERROR  [{case['id']}] {e}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / len(TEST_CORPUS)

    return {
        "layer": layer_name,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "errors": errors
    }

def predict_rules(stmt):
    findings = check_statement(stmt, "eval")
    return any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)

def predict_opa(stmt):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(make_plan(stmt), f)
        path = f.name
    try:
        violations = analyze_opa(path)
        return any(v.get("severity") in ("HIGH", "CRITICAL") for v in violations)
    finally:
        os.unlink(path)

def predict_ml(stmt):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(make_plan(stmt), f)
        path = f.name
    try:
        results = analyze_ml(path)
        return any(r["anomaly_score"] >= 70 for r in results)
    finally:
        os.unlink(path)

def predict_combined(stmt):
    return predict_rules(stmt) or predict_opa(stmt)

def print_results(results):
    print("\n" + "="*60)
    print("FORMAL EVALUATION REPORT")
    print(f"Test corpus: {len(TEST_CORPUS)} cases "
          f"({sum(1 for c in TEST_CORPUS if c['label'])} TP scenarios, "
          f"{sum(1 for c in TEST_CORPUS if not c['label'])} TN scenarios)")
    print("="*60)

    headers = f"{'Layer':<20} {'P':>6} {'R':>6} {'F1':>6} {'Acc':>6} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}"
    print(f"\n{headers}")
    print("-"*60)

    for r in results:
        print(
            f"{r['layer']:<20} "
            f"{r['precision']:>6.3f} "
            f"{r['recall']:>6.3f} "
            f"{r['f1']:>6.3f} "
            f"{r['accuracy']:>6.3f} "
            f"{r['tp']:>4} "
            f"{r['fp']:>4} "
            f"{r['tn']:>4} "
            f"{r['fn']:>4}"
        )

    print("\n" + "="*60)
    best = max(results, key=lambda x: x["f1"])
    print(f"Best F1 score  : {best['layer']} ({best['f1']:.3f})")
    combined = next((r for r in results if r["layer"] == "Combined"), None)
    if combined:
        print(f"Combined layer : F1={combined['f1']:.3f}  Precision={combined['precision']:.3f}  Recall={combined['recall']:.3f}")

    print("\nMissed detections & false positives:")
    for r in results:
        if r["errors"]:
            print(f"\n  [{r['layer']}]")
            for e in r["errors"]:
                print(f"  {e}")

    print("\n" + "="*60)
    print("METHODOLOGY")
    print("  Precision = TP / (TP + FP)  — of flagged, how many were real")
    print("  Recall    = TP / (TP + FN)  — of real threats, how many caught")
    print("  F1        = harmonic mean of Precision and Recall")
    print("="*60 + "\n")

if __name__ == "__main__":
    print("Running formal evaluation across all detection layers...")
    print("This may take 30-60 seconds for OPA and ML layers.\n")

    results = []
    results.append(evaluate_layer("Rule-based",    predict_rules))
    results.append(evaluate_layer("OPA/Rego",      predict_opa))
    results.append(evaluate_layer("ML (IsoForest)",predict_ml))
    results.append(evaluate_layer("Combined",      predict_combined))
    print_results(results)
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from check_drift import check_statement, scan_plan
import tempfile

def make_stmt(actions, resources, effect="Allow"):
    return {"Effect": effect, "Action": actions, "Resource": resources}

def test_wildcard_action_is_high():
    findings = check_statement(make_stmt(["*"], ["*"]), "test_resource")
    assert any(f["severity"] == "HIGH" for f in findings)

def test_passrole_wildcard_is_high():
    findings = check_statement(make_stmt(["iam:PassRole"], ["*"]), "test_resource")
    assert any("PassRole" in f["reason"] for f in findings)

def test_s3_delete_is_high():
    findings = check_statement(make_stmt(["s3:DeleteBucket"], ["*"]), "test_resource")
    assert any(f["severity"] == "HIGH" for f in findings)

def test_ec2_wildcard_is_high():
    findings = check_statement(make_stmt(["ec2:*"], ["*"]), "test_resource")
    assert any(f["severity"] == "HIGH" for f in findings)

def test_deny_effect_ignored():
    findings = check_statement(make_stmt(["*"], ["*"], effect="Deny"), "test_resource")
    assert len(findings) == 0

def test_safe_policy_passes():
    findings = check_statement(
        make_stmt(["s3:GetObject"], ["arn:aws:s3:::my-bucket/*"]), "test_resource"
    )
    assert len(findings) == 0

def test_full_plan_scan():
    plan = {
        "resource_changes": [{
            "address": "aws_iam_role_policy.bad",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "policy": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "s3:DeleteBucket"],
                            "Resource": "*"
                        }]
                    })
                }
            }
        }]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(plan, f)
        path = f.name
    findings = scan_plan(path)
    assert len(findings) >= 2
    assert all(f["severity"] == "HIGH" for f in findings)
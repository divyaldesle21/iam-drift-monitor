package iam.drift

import future.keywords.if
import future.keywords.in

# -------------------------------------------------------
# Rule 1: Deny wildcard actions
# MITRE ATT&CK: T1078 - Valid Accounts
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    action == "*"
    result := {
        "rule_id": "IAM001",
        "severity": "CRITICAL",
        "title": "Wildcard action grants full AWS access",
        "mitre": "T1078",
        "action": action,
        "remediation": "Replace '*' with specific required actions"
    }
}

# -------------------------------------------------------
# Rule 2: Deny iam:PassRole with wildcard resource
# MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    "iam:PassRole" in stmt.Action
    resource := stmt.Resource[_]
    resource == "*"
    result := {
        "rule_id": "IAM002",
        "severity": "CRITICAL",
        "title": "iam:PassRole with wildcard resource enables privilege escalation",
        "mitre": "T1548",
        "action": "iam:PassRole",
        "remediation": "Scope Resource to specific role ARNs only"
    }
}

# -------------------------------------------------------
# Rule 3: Deny destructive S3 actions
# MITRE ATT&CK: T1485 - Data Destruction
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    action in {"s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteBucketPolicy"}
    resource := stmt.Resource[_]
    resource == "*"
    result := {
        "rule_id": "IAM003",
        "severity": "HIGH",
        "title": sprintf("Destructive S3 action '%v' with wildcard resource", [action]),
        "mitre": "T1485",
        "action": action,
        "remediation": "Scope to specific bucket ARN and remove destructive permissions"
    }
}

# -------------------------------------------------------
# Rule 4: Deny IAM privilege escalation actions
# MITRE ATT&CK: T1548
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    action in {
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy"
    }
    resource := stmt.Resource[_]
    resource == "*"
    result := {
        "rule_id": "IAM004",
        "severity": "HIGH",
        "title": sprintf("IAM escalation action '%v' with wildcard resource", [action]),
        "mitre": "T1548",
        "action": action,
        "remediation": "Scope to specific IAM role/user ARNs"
    }
}

# -------------------------------------------------------
# Rule 5: Deny secrets access with wildcard
# MITRE ATT&CK: T1552 - Unsecured Credentials
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    action in {"secretsmanager:GetSecretValue", "kms:Decrypt", "ssm:GetParameter"}
    resource := stmt.Resource[_]
    resource == "*"
    result := {
        "rule_id": "IAM005",
        "severity": "HIGH",
        "title": sprintf("Credential access action '%v' with wildcard resource", [action]),
        "mitre": "T1552",
        "action": action,
        "remediation": "Scope to specific secret/key ARNs"
    }
}

# -------------------------------------------------------
# Rule 6: Warn on overly broad EC2 permissions
# MITRE ATT&CK: T1578 - Modify Cloud Compute Infrastructure
# -------------------------------------------------------
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    startswith(action, "ec2:")
    endswith(action, "*")
    result := {
        "rule_id": "IAM006",
        "severity": "MEDIUM",
        "title": sprintf("Overly broad EC2 permission '%v'", [action]),
        "mitre": "T1578",
        "action": action,
        "remediation": "Replace with specific EC2 actions required"
    }
}
# Rule 7: Wildcard service permissions (s3:*, lambda:*, cloudwatch:*)
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    endswith(action, ":*")
    not startswith(action, "ec2:")  # ec2:* already caught by IAM006
    resource := stmt.Resource[_]
    resource == "*"
    result := {
        "rule_id": "IAM007",
        "severity": "HIGH",
        "title": sprintf("Wildcard service permission '%v' grants full service access", [action]),
        "mitre": "T1078",
        "action": action,
        "remediation": sprintf("Replace '%v' with specific required actions for this service", [action])
    }
}

# Rule 8: Multiple wildcard services — CRITICAL
violation[result] {
    stmt := input.statement
    stmt.Effect == "Allow"
    wildcards := [a | a := stmt.Action[_]; endswith(a, ":*")]
    count(wildcards) >= 3
    result := {
        "rule_id": "IAM008",
        "severity": "CRITICAL",
        "title": sprintf("Multiple wildcard service permissions (%v services) — near-admin equivalent", [count(wildcards)]),
        "mitre": "T1078",
        "action": concat(", ", wildcards),
        "remediation": "Replace all wildcard permissions with specific least-privilege actions"
    }
}
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# -------------------------------------------------------
# IAM Role — CI/CD Deploy Role (safe trust policy)
# -------------------------------------------------------
resource "aws_iam_role" "ci_role" {
  name = "ci-deploy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# -------------------------------------------------------
# VULNERABLE POLICY 1 — Privilege Escalation
# Flags: iam:PassRole + wildcard, s3:DeleteBucket, ec2:*
# MITRE: T1548, T1485, T1578
# -------------------------------------------------------
resource "aws_iam_role_policy" "bad_policy" {
  name = "overprivileged-policy"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole", "s3:DeleteBucket", "ec2:*"]
        Resource = "*"
      }
    ]
  })
}

# -------------------------------------------------------
# VULNERABLE POLICY 2 — Full Admin Wildcard
# Flags: Action:* — full administrator equivalent
# MITRE: T1078
# -------------------------------------------------------
resource "aws_iam_role_policy" "extra_bad_policy" {
  name = "extra-overprivileged"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = "*"
      }
    ]
  })
}

# -------------------------------------------------------
# VULNERABLE POLICY 3 — IAM Escalation Chain
# Flags: CreateRole + AttachRolePolicy + CreatePolicyVersion
# MITRE: T1548 — graph engine catches this as attack chain
# -------------------------------------------------------
resource "aws_iam_role_policy" "escalation_policy" {
  name = "iam-escalation-policy"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# -------------------------------------------------------
# VULNERABLE POLICY 4 — Credential & Audit Evasion
# Flags: secretsmanager, kms:Decrypt, cloudtrail:StopLogging
# MITRE: T1552, T1562
# -------------------------------------------------------
resource "aws_iam_role_policy" "credential_and_evasion_policy" {
  name = "credential-evasion-policy"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "ssm:GetParameter"
        ]
        Resource = "*"
      }
    ]
  })
}

# -------------------------------------------------------
# SAFE POLICY — Least privilege example (should NOT flag)
# Only s3:GetObject scoped to specific bucket ARN
# -------------------------------------------------------
resource "aws_iam_role_policy" "safe_policy" {
  name = "least-privilege-policy"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "arn:aws:s3:::my-deploy-bucket/*"
      }
    ]
  })
}
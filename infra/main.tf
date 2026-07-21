```hcl
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

resource "aws_iam_role" "ci_role" {
  name               = "ci-deploy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect  = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action  = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "bad_policy" {
  name = "overprivileged-policy"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = "arn:aws:iam::*:role/ci-deploy-role"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:DeleteBucket"
        ]
        Resource = "arn:aws:s3:::ci-deployment-bucket"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:DescribeSecurityGroups",
          "ec2:RunInstances",
          "ec2:TerminateInstances"
        ]
        Resource = [
          "arn:aws:ec2:*:*:instance/*",
          "arn:aws:ec2:*:*:security-group/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "extra_bad_policy" {
  name = "extra-overprivileged"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::ci-deployment-bucket",
          "arn:aws:s3:::ci-deployment-bucket/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/ci-deploy*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "escalation_policy" {
  name = "controlled-iam-permissions"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:ListPolicies",
          "iam:GetRole",
          "iam:GetPolicy"
        ]
        Resource = [
          "arn:aws:iam::*:role/ci-deploy-role",
          "arn:aws:iam::*:policy/ci-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "credential_and_evasion_policy" {
  name = "controlled-secrets-access"
  role = aws_iam_role.ci_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        
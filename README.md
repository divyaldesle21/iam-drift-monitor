# Containerized CI/CD IAM Privilege-Drift Monitor

An automated security gate that scans Infrastructure-as-Code pull requests for over-privileged IAM changes, blocks deployments, and alerts via Discord/Slack.

## What It Does

Every time a pull request modifies a Terraform IAM policy, this tool:
1. Builds a Docker container with Checkov + custom Python scanner
2. Parses the Terraform plan JSON for dangerous IAM patterns
3. Fails the build and blocks the merge if HIGH severity findings are detected
4. Fires a real-time Discord/Slack alert with the exact resource and reason

## Risk Patterns Detected

| Pattern | Severity |
|---|---|
| `iam:PassRole` with wildcard resource | HIGH |
| Wildcard `Action: "*"` | HIGH |
| `s3:DeleteBucket` with wildcard resource | HIGH |
| `ec2:*` with wildcard resource | HIGH |
| Wildcard `Resource: "*"` alone | MEDIUM |

## Project Structure

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/divyaldesle21/iam-drift-monitor.git
cd iam-drift-monitor
```

### 2. Add GitHub Secrets
Go to repo Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `DISCORD_WEBHOOK` | Your Discord webhook URL |
| `AWS_ACCESS_KEY_ID` | AWS IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM user secret key |

### 3. Enable branch protection
Settings → Branches → Add rule → require `IAM Privilege Drift Scan` to pass

### 4. Test locally
```bash
docker build -t iam-drift-monitor .
docker run --rm -v "${PWD}:/app" iam-drift-monitor /app/plan.json
```

### 5. Run tests
```bash
docker run --rm -v "${PWD}:/app" --entrypoint pytest iam-drift-monitor /app/tests/test_drift.py -v
```

## How It Works

## Demo

Open a PR with a vulnerable IAM policy:
- Build fails with `BUILD BLOCKED — HIGH severity findings detected`
- Merge button is blocked by branch protection
- Discord alert fires with resource name and violation reason

Fix the policy to least-privilege → build passes → merge allowed.

## Tech Stack

GitHub Actions · Docker · Python 3.12 · Checkov · TFLint · Terraform · AWS IAM · Discord Webhooks · pytest

## Author

Divyal Desle — M.S. Cybersecurity, University of Denver
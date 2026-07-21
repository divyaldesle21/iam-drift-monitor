# Containerized CI/CD IAM Privilege-Drift Monitor

A multi-layer security gate that scans every Terraform pull request for over-privileged IAM changes, blocks dangerous merges, simulates attacker impact, and autonomously generates fixes.

## What It Does

Every pull request that modifies a Terraform IAM policy triggers an 11-layer detection pipeline running inside Docker:

1. Rule-based engine - 15 dangerous IAM action patterns
2. Graph attack paths - multi-hop escalation chains (NetworkX + MITRE ATT&CK)
3. OPA/Rego policy engine - 6 declarative rules with MITRE mappings
4. ML anomaly detection - supervised Random Forest (F1=0.929)
5. Blast radius simulator - quantifies attacker impact 0-100
6. AI Red Team Agent - Claude AI autonomously plans attack chains
7. Policy DNA engine - Smith-Waterman genome alignment vs known attacks
8. Self-healing auto-PR bot - generates least-privilege fix automatically
9. Temporal drift analysis - mines git history for slow-burn creep
10. Honeypot permission layer - canary-based deception detection
11. SARIF integration - GitHub Security tab native reporting

## Evaluation Results

| Layer | Precision | Recall | F1 |
|---|---|---|---|
| Rule-based | 1.000 | 1.000 | 1.000 |
| OPA/Rego | 1.000 | 0.733 | 0.846 |
| ML Random Forest | 1.000 | 0.867 | 0.929 |
| Combined System | 1.000 | 1.000 | 1.000 |

Evaluated against 30-case labeled corpus AND TerraGoat real-world vulnerabilities.
TerraGoat blast radius: 100/100 CATASTROPHIC - 5 active attack chains detected.

## Real-World Evaluation - TerraGoat

Tested against TerraGoat (Bridgecrew deliberately vulnerable infrastructure):
- 4 HIGH rule violations detected
- 5 OPA policy violations (1 CRITICAL IAM008 - T1078)
- 2 graph escalation paths
- Blast radius: 100/100 CATASTROPHIC
- Attack chains: Full Data Exfiltration (T1530), Compute Takeover (T1578), Monitoring Blind Spot (T1562)

## Quick Start

docker build -t iam-drift-monitor .
docker run --rm -v PWD:/app iam-drift-monitor /app/plan.json

## All Commands

Full scan:      docker run --rm -v PWD:/app iam-drift-monitor /app/plan.json
Blast radius:   docker run --rm -v PWD:/app --entrypoint python iam-drift-monitor /app/scripts/blast_radius.py /app/plan.json
AI Red Team:    docker run --rm -v PWD:/app --env-file .env --entrypoint python iam-drift-monitor /app/scripts/ai_red_team.py /app/plan.json
Policy DNA:     docker run --rm -v PWD:/app --entrypoint python iam-drift-monitor /app/scripts/policy_dna.py /app/plan.json
Temporal drift: docker run --rm -v PWD:/app --entrypoint python iam-drift-monitor /app/scripts/temporal_analyzer.py /app infra/main.tf
Honeypot:       docker run --rm -v PWD:/app --entrypoint python iam-drift-monitor /app/scripts/honeypot.py /app/plan.json
Tests:          docker run --rm -v PWD:/app --entrypoint pytest iam-drift-monitor /app/tests/test_drift.py -v
Evaluation:     docker run --rm -v PWD:/app --entrypoint python iam-drift-monitor /app/scripts/evaluator.py

## MITRE ATT&CK Coverage

T1548 - Privilege Escalation     - Rules, OPA, Graph
T1485 - Data Destruction         - Rules, OPA
T1552 - Credential Access        - Rules, OPA, Honeypot
T1562 - Defense Evasion          - Rules, OPA, Honeypot
T1578 - Compute Modification     - Rules, OPA, Blast Radius
T1078 - Valid Accounts           - OPA, DNA
T1648 - Serverless Execution     - Graph, Blast Radius
T1530 - Data from Cloud Storage  - Blast Radius

## Tech Stack

Docker, Python 3.12, Checkov, TFLint, OPA/Rego, NetworkX, scikit-learn, BioPython, GitHub Actions, SARIF, Discord Webhooks, Claude AI

## Author

Divyal Desle - M.S. Cybersecurity, University of Denver, 2026
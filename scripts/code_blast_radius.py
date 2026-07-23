import os
import sys
import re

# -------------------------------------------------------
# CWE IMPACT MODEL
# Maps each vulnerability class to real attacker capability
# -------------------------------------------------------
CWE_IMPACT = {
    "CWE-89": {
        "name": "SQL Injection",
        "base_severity": 10,
        "capabilities": [
            "Read entire database (users, passwords, PII)",
            "Modify or delete any record",
            "Extract password hashes for offline cracking",
            "Potential RCE via stacked queries or xp_cmdshell"
        ],
        "attack_chain": "input -> query -> full DB compromise",
        "owasp": "A03:2021 Injection"
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "base_severity": 10,
        "capabilities": [
            "Execute arbitrary OS commands as the app user",
            "Read /etc/passwd, environment variables, secrets",
            "Establish reverse shell for persistent access",
            "Pivot to internal network"
        ],
        "attack_chain": "input -> shell -> remote code execution",
        "owasp": "A03:2021 Injection"
    },
    "CWE-94": {
        "name": "Code Injection",
        "base_severity": 10,
        "capabilities": [
            "Execute arbitrary code in application runtime",
            "Access all application memory and secrets",
            "Bypass all application-level security controls"
        ],
        "attack_chain": "input -> eval -> arbitrary code execution",
        "owasp": "A03:2021 Injection"
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "base_severity": 9,
        "capabilities": [
            "Remote code execution via crafted objects",
            "Gadget chain exploitation",
            "Application logic manipulation"
        ],
        "attack_chain": "input -> deserialize -> RCE",
        "owasp": "A08:2021 Data Integrity Failures"
    },
    "CWE-22": {
        "name": "Path Traversal",
        "base_severity": 7,
        "capabilities": [
            "Read arbitrary files (/etc/passwd, config, keys)",
            "Access AWS credentials in ~/.aws/credentials",
            "Read application source code and secrets"
        ],
        "attack_chain": "input -> file path -> arbitrary file read",
        "owasp": "A01:2021 Broken Access Control"
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "base_severity": 8,
        "capabilities": [
            "Access cloud metadata (169.254.169.254) for IAM creds",
            "Scan and reach internal network services",
            "Bypass firewalls via server as proxy"
        ],
        "attack_chain": "input -> HTTP request -> cloud credential theft",
        "owasp": "A10:2021 SSRF"
    },
    "CWE-79": {
        "name": "Cross-Site Scripting",
        "base_severity": 6,
        "capabilities": [
            "Steal session cookies and hijack accounts",
            "Keylog and phish credentials",
            "Perform actions as the victim user"
        ],
        "attack_chain": "input -> HTML output -> session hijack",
        "owasp": "A03:2021 Injection"
    },
    "CWE-611": {
        "name": "XML External Entity",
        "base_severity": 7,
        "capabilities": [
            "Read local files via external entities",
            "SSRF to internal services",
            "Denial of service via billion laughs"
        ],
        "attack_chain": "XML input -> entity -> file disclosure",
        "owasp": "A05:2021 Security Misconfiguration"
    },
    "CWE-90": {
        "name": "LDAP Injection",
        "base_severity": 7,
        "capabilities": [
            "Bypass authentication",
            "Enumerate directory users and groups",
            "Escalate directory privileges"
        ],
        "attack_chain": "input -> LDAP filter -> auth bypass",
        "owasp": "A03:2021 Injection"
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "base_severity": 9,
        "capabilities": [
            "Direct authentication with embedded credentials",
            "AWS account access if cloud keys hardcoded",
            "Lateral movement using shared secrets"
        ],
        "attack_chain": "read source -> extract creds -> authenticated access",
        "owasp": "A07:2021 Identification and Authentication Failures"
    },
}

# Vulnerability chaining ? how one vuln enables another
VULN_CHAINS = [
    {
        "name": "Path Traversal to Credential Theft to Cloud Takeover",
        "required": ["CWE-22", "CWE-798"],
        "description": "Read config files via path traversal, extract hardcoded AWS keys, compromise cloud account",
        "severity": "CRITICAL"
    },
    {
        "name": "SSRF to Cloud Metadata to IAM Compromise",
        "required": ["CWE-918"],
        "description": "SSRF to 169.254.169.254 steals IAM role credentials, full AWS access",
        "severity": "CRITICAL"
    },
    {
        "name": "SQL Injection to Credential Harvest to Lateral Movement",
        "required": ["CWE-89", "CWE-798"],
        "description": "Extract password hashes via SQLi, crack offline, reuse across systems",
        "severity": "CRITICAL"
    },
    {
        "name": "Command Injection to Reverse Shell to Persistence",
        "required": ["CWE-78"],
        "description": "Command injection establishes reverse shell, attacker gains persistent server access",
        "severity": "CRITICAL"
    },
    {
        "name": "Full Injection Chain",
        "required": ["CWE-89", "CWE-78"],
        "description": "Both SQL and command injection present - database and OS fully compromised",
        "severity": "CRITICAL"
    },
]

def scan_for_cwes(repo_path):
    """Import taint analysis findings and extract CWEs present"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from taint_analysis import scan_directory
        findings, files = scan_directory(repo_path)
        cwes_found = {}
        for f in findings:
            cwe = f["cwe"]
            cwes_found.setdefault(cwe, []).append(f)
        return cwes_found, files
    except Exception as e:
        print(f"Could not import taint analysis: {e}")
        return {}, 0

def compute_code_blast_radius(cwes_found):
    total_severity = 0
    active_capabilities = []

    for cwe, findings in cwes_found.items():
        if cwe in CWE_IMPACT:
            impact = CWE_IMPACT[cwe]
            total_severity += impact["base_severity"]
            active_capabilities.append({
                "cwe": cwe,
                "name": impact["name"],
                "capabilities": impact["capabilities"],
                "attack_chain": impact["attack_chain"],
                "count": len(findings),
                "owasp": impact["owasp"]
            })

    active_chains = []
    present_cwes = set(cwes_found.keys())
    for chain in VULN_CHAINS:
        if all(req in present_cwes for req in chain["required"]):
            active_chains.append(chain)

    blast_score = min(100, (total_severity * 4) + (len(active_chains) * 12))

    return {
        "blast_score": blast_score,
        "capabilities": active_capabilities,
        "attack_chains": active_chains,
        "cwe_count": len(cwes_found),
        "total_severity": total_severity
    }

def print_code_blast_report(result, files_scanned):
    score = result["blast_score"]
    caps = result["capabilities"]
    chains = result["attack_chains"]

    if score >= 80:
        level = "CATASTROPHIC -- Full application and cloud compromise likely"
    elif score >= 60:
        level = "CRITICAL -- Remote code execution or data breach possible"
    elif score >= 40:
        level = "HIGH -- Significant application compromise possible"
    elif score >= 20:
        level = "MEDIUM -- Limited exploitation possible"
    else:
        level = "LOW -- Minimal impact"

    bar = "X" * (score // 5) + "." * (20 - score // 5)

    print("\n" + "="*70)
    print("CODE VULNERABILITY BLAST RADIUS")
    print("Application Attack Impact Quantification | CWE + OWASP Mapped")
    print("="*70)
    print(f"\nFiles analyzed  : {files_scanned}")
    print(f"Blast Score     : [{bar}] {score}/100")
    print(f"Threat Level    : {level}")
    print(f"CWE classes     : {result['cwe_count']}")
    print(f"Attack chains   : {len(chains)}")

    if caps:
        print(f"\nATTACKER CAPABILITIES UNLOCKED:")
        print("-"*70)
        for cap in sorted(caps, key=lambda x: -CWE_IMPACT[x["cwe"]]["base_severity"]):
            print(f"\n  [{cap['cwe']}] {cap['name']} ({cap['count']} instance(s))")
            print(f"  OWASP: {cap['owasp']}")
            print(f"  Attack chain: {cap['attack_chain']}")
            for c in cap["capabilities"]:
                print(f"     - {c}")

    if chains:
        print(f"\nACTIVE EXPLOIT CHAINS ({len(chains)}):")
        print("="*70)
        for chain in chains:
            print(f"\n  [{chain['severity']}] {chain['name']}")
            print(f"  {chain['description']}")
            print(f"  Requires: {' + '.join(chain['required'])}")

    print("\n" + "="*70)
    print(f"BLAST RADIUS VERDICT: {level}")
    print("="*70 + "\n")
    return score >= 40

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print(f"Computing code vulnerability blast radius for: {repo_path}")
    cwes_found, files = scan_for_cwes(repo_path)
    result = compute_code_blast_radius(cwes_found)
    blocked = print_code_blast_report(result, files)
    sys.exit(1 if blocked else 0)
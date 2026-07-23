import os
import sys
import json
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

def call_claude(prompt):
    if not ANTHROPIC_API_KEY:
        return "ERROR: ANTHROPIC_API_KEY not set"
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1200,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={"Content-Type": "application/json", "x-api-key": ANTHROPIC_API_KEY,
                 "anthropic-version": "2023-06-01"},
        method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())["content"][0]["text"]
    except urllib.error.HTTPError as e:
        return "API error " + str(e.code) + ": " + e.read().decode()[:200]
    except Exception as e:
        return "Error: " + str(e)

def gather_findings(repo_path):
    from taint_analysis import scan_directory
    findings, n = scan_directory(repo_path)
    by_cwe = {}
    for f in findings:
        c = f["cwe"]
        if c not in by_cwe:
            by_cwe[c] = {"name": f["vulnerability"], "count": 0, "example": None}
        by_cwe[c]["count"] += 1
        if by_cwe[c]["example"] is None:
            loc = os.path.relpath(f["file"], repo_path)
            line = f.get("line") or f.get("sink_line") or "?"
            code = f.get("code") or f.get("sink_code") or ""
            by_cwe[c]["example"] = loc + ":" + str(line) + "  ->  " + code
    return by_cwe, n

def run_agent(by_cwe, n_files):
    vuln_summary = "\n".join(
        "- " + cwe + " " + d["name"] + " (" + str(d["count"]) + " instances). Example: " + (d["example"] or "")
        for cwe, d in sorted(by_cwe.items(), key=lambda x: -x[1]["count"])
    )
    prompt = (
        "You are an expert application penetration tester performing authorized "
        "security assessment of an open-source web application (OWASP WebGoat).\n\n"
        "A SAST scan of " + str(n_files) + " source files found these vulnerabilities:\n\n"
        + vuln_summary + "\n\n"
        "Produce a realistic exploitation plan that chains these code-level vulnerabilities "
        "from initial access to full compromise. For each step give:\n"
        "STEP N, VULNERABILITY (CWE), the concrete exploit action against the source code, "
        "the CWE/OWASP reference, and what the attacker gains.\n"
        "Then chain steps together (e.g. XSS steals a session, session reaches a SQL endpoint, "
        "SQLi dumps credentials). End with BUSINESS IMPACT and a RISK RATING.\n"
        "Be specific and technical about the application layer - not infrastructure or IAM."
    )
    return call_claude(prompt)

def print_report(by_cwe, n_files, narrative):
    print("\n" + "=" * 72)
    print("AI RED TEAM AGENT - APPLICATION EXPLOITATION")
    print("Powered by Claude AI | Attacks Source-Code Vulnerabilities | CWE/OWASP")
    print("=" * 72)
    print("\nSource files analyzed : " + str(n_files))
    print("Vulnerability classes : " + str(len(by_cwe)))
    print("\nSAST FINDINGS PROVIDED TO AGENT:")
    print("-" * 72)
    for cwe, d in sorted(by_cwe.items(), key=lambda x: -x[1]["count"]):
        print("  " + cwe.ljust(11) + d["name"][:34].ljust(36) + str(d["count"]).rjust(4) + " sites")
    print("\n" + "-" * 72)
    print("AUTONOMOUS EXPLOITATION PLAN:")
    print("-" * 72 + "\n")
    print(narrative)
    print("\n" + "=" * 72)
    print("END OF APPLICATION RED TEAM SIMULATION")
    print("=" * 72 + "\n")

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print("Gathering SAST findings from: " + repo)
    by_cwe, n = gather_findings(repo)
    if not by_cwe:
        print("No vulnerabilities found to exploit.")
        sys.exit(0)
    print("Running AI application red team... 10-20 seconds")
    narrative = run_agent(by_cwe, n)
    print_report(by_cwe, n, narrative)
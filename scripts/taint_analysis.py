import os
import sys
import re

TAINT_SOURCES = {
    "python": [r"request\.(args|form|json|data|values|cookies|headers)", r"\binput\s*\(", r"sys\.argv"],
    "java": [r"request\.getParameter\s*\(", r"request\.getHeader\s*\(", r"\.getRawParameter\s*\(", r"\.getParameterValues\s*\(", r"getParser\s*\(\s*\)\s*\.\s*get\w*Parameter"],
    "javascript": [r"req\.(body|query|params|cookies|headers)", r"location\.(search|hash|href)"],
    "php": [r"\$_(GET|POST|REQUEST|COOKIE|FILES)"]
}

DIRECT_PATTERNS = {
    "sql_concat": {
        "patterns": [
            r"(?i)\w+\s*=\s*\"\s*SELECT\s+[^\"]*\"\s*\+",
            r"(?i)\w+\s*=\s*\"\s*INSERT\s+INTO[^\"]*\"\s*\+",
            r"(?i)\w+\s*=\s*\"\s*UPDATE\s+[^\"]*\"\s*\+",
            r"(?i)\w+\s*=\s*\"\s*DELETE\s+FROM[^\"]*\"\s*\+",
            r"(?i)executeQuery\s*\(\s*\"[^\"]*\"\s*\+",
        ],
        "cwe": "CWE-89", "name": "SQL Injection (string concatenation)",
        "severity": "CRITICAL", "owasp": "A03:2021 Injection",
        "impact": "Query built by concatenation - attacker controls SQL structure",
        "why": "SQL built with string concatenation instead of parameterized query"
    },
    "cmd_concat": {
        "patterns": [
            r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[^\")]*\+",
            r"os\.system\s*\(\s*[^\")]*\+",
            r"subprocess\.\w+\s*\(\s*[^\")]*\+",
            r"shell_exec\s*\(\s*[^\")]*\+",
        ],
        "cwe": "CWE-78", "name": "OS Command Injection (concatenation)",
        "severity": "CRITICAL", "owasp": "A03:2021 Injection",
        "impact": "Shell command built by concatenation - remote code execution",
        "why": "OS command constructed with untrusted concatenation"
    },
    "hardcoded_aws": {
        "patterns": [r"AKIA[0-9A-Z]{16}"],
        "cwe": "CWE-798", "name": "Hardcoded AWS Access Key",
        "severity": "CRITICAL", "owasp": "A07:2021 Auth Failures",
        "impact": "Live AWS credentials exposed in source control",
        "why": "AWS Access Key ID literal found in source"
    },
    "weak_crypto": {
        "patterns": [r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)\"", r"hashlib\.(md5|sha1)\s*\("],
        "cwe": "CWE-327", "name": "Weak Cryptographic Hash",
        "severity": "HIGH", "owasp": "A02:2021 Cryptographic Failures",
        "impact": "Hash is collision-prone and unsuitable for security use",
        "why": "MD5/SHA-1 used for security purposes"
    },
}

DANGEROUS_SINKS = {
    "sql_injection": {
        "patterns": [r"executeQuery\s*\(", r"executeUpdate\s*\(", r"cursor\.execute\s*\("],
        "cwe": "CWE-89", "name": "SQL Injection", "severity": "CRITICAL",
        "owasp": "A03:2021 Injection", "impact": "Full database compromise"
    },
    "command_injection": {
        "patterns": [r"Runtime\.getRuntime\(\)\.exec\s*\(", r"os\.system\s*\(", r"subprocess\.(call|run|Popen)\s*\("],
        "cwe": "CWE-78", "name": "OS Command Injection", "severity": "CRITICAL",
        "owasp": "A03:2021 Injection", "impact": "Remote code execution"
    },
    "path_traversal": {
        "patterns": [r"new\s+File\s*\(", r"new\s+FileInputStream\s*\(", r"Paths\.get\s*\("],
        "cwe": "CWE-22", "name": "Path Traversal", "severity": "HIGH",
        "owasp": "A01:2021 Broken Access Control", "impact": "Arbitrary file read"
    },
    "xss": {
        "patterns": [r"response\.getWriter\s*\(\s*\)", r"getWriter\s*\(\s*\)\s*\.\s*(write|print)", r"innerHTML\s*=", r"document\.write\s*\("],
        "cwe": "CWE-79", "name": "Cross-Site Scripting", "severity": "HIGH",
        "owasp": "A03:2021 Injection", "impact": "Session hijacking, account takeover"
    },
    "ssrf": {
        "patterns": [r"new\s+URL\s*\(", r"openConnection\s*\(", r"requests\.(get|post)\s*\("],
        "cwe": "CWE-918", "name": "Server-Side Request Forgery", "severity": "HIGH",
        "owasp": "A10:2021 SSRF", "impact": "Cloud metadata theft, internal network access"
    },
}

SANITIZERS = [r"PreparedStatement", r"setString\s*\(", r"setInt\s*\(", r"prepareStatement", r"prepareCall", r"escape\s*\(", r"sanitize", r"htmlspecialchars", r"encodeURIComponent", r"DOMPurify", r"Pattern\.quote", r"shlex\.quote"]

EXT_LANG = {".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".php": "php"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", "target", "venv"}

def detect_language(fp):
    return EXT_LANG.get(os.path.splitext(fp)[1].lower())

def is_noise(content, pos):
    ls = content.rfind("\n", 0, pos) + 1
    prefix = content[ls:pos]
    s = prefix.lstrip()
    full_line = content[ls:content.find(chr(10), pos) if content.find(chr(10), pos) > 0 else len(content)]
    if "hints.add" in full_line or "getInstructions" in full_line or "<br>" in full_line:
        return True
    return s.startswith("//") or s.startswith("#") or s.startswith("*")

def line_of(content, pos):
    return content[:pos].count("\n") + 1

def find_direct_patterns(fp, content):
    out = []
    lines = content.split("\n")
    for key, d in DIRECT_PATTERNS.items():
        for pat in d["patterns"]:
            for m in re.finditer(pat, content):
                if is_noise(content, m.start()):
                    continue
                ln = line_of(content, m.start())
                code = lines[ln-1].strip()[:110] if ln <= len(lines) else ""
                out.append({
                    "kind": "direct", "file": fp, "vulnerability": d["name"],
                    "cwe": d["cwe"], "severity": d["severity"], "owasp": d["owasp"],
                    "impact": d["impact"], "why": d["why"],
                    "line": ln, "code": code
                })
    return out

def find_taint_sources(content, lang):
    out = []
    for pat in TAINT_SOURCES.get(lang, []):
        for m in re.finditer(pat, content):
            if is_noise(content, m.start()):
                continue
            out.append({"line": line_of(content, m.start()), "text": m.group(0)})
    return out

def find_sinks(content):
    out = []
    for stype, d in DANGEROUS_SINKS.items():
        for pat in d["patterns"]:
            for m in re.finditer(pat, content):
                if is_noise(content, m.start()):
                    continue
                out.append({"line": line_of(content, m.start()), "cwe": d["cwe"],
                            "name": d["name"], "severity": d["severity"],
                            "owasp": d["owasp"], "impact": d["impact"]})
    return out

def sanitized_near(content, sink_line):
    lines = content.split("\n")
    seg = "\n".join(lines[max(0, sink_line-4):sink_line+1])
    return any(re.search(s, seg) for s in SANITIZERS)

def find_taint_flows(fp, content, lang):
    out = []
    sources = find_taint_sources(content, lang)
    sinks = find_sinks(content)
    lines = content.split("\n")
    for src in sources:
        for snk in sinks:
            dist = snk["line"] - src["line"]
            if not (0 <= dist <= 50):
                continue
            if sanitized_near(content, snk["line"]):
                continue
            out.append({
                "kind": "flow", "file": fp, "vulnerability": snk["name"],
                "cwe": snk["cwe"], "severity": snk["severity"], "owasp": snk["owasp"],
                "impact": snk["impact"],
                "source_line": src["line"],
                "source_code": lines[src["line"]-1].strip()[:100] if src["line"] <= len(lines) else "",
                "sink_line": snk["line"],
                "sink_code": lines[snk["line"]-1].strip()[:100] if snk["line"] <= len(lines) else "",
                "distance": dist,
                "confidence": "HIGH" if dist <= 20 else "MEDIUM"
            })
    return out

def scan_directory(repo_path):
    findings = []
    n = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for fn in files:
            fp = os.path.join(root, fn)
            lang = detect_language(fp)
            if not lang:
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            n += 1
            findings.extend(find_direct_patterns(fp, content))
            findings.extend(find_taint_flows(fp, content, lang))
    return findings, n

def print_report(findings, n, repo_path):
    print("\n" + "=" * 72)
    print("STATIC APPLICATION SECURITY TESTING (SAST) ENGINE")
    print("Direct Pattern Detection + Data-Flow Taint Tracing")
    print("CWE + OWASP Top 10 Mapped")
    print("=" * 72)
    direct = [f for f in findings if f["kind"] == "direct"]
    flows = [f for f in findings if f["kind"] == "flow"]
    crit = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    print("\nFiles analyzed        : " + str(n))
    print("Total findings        : " + str(len(findings)))
    print("  Direct patterns     : " + str(len(direct)))
    print("  Taint flows         : " + str(len(flows)))
    print("CRITICAL              : " + str(len(crit)))
    print("HIGH                  : " + str(len(high)))
    if not findings:
        print("\nNo security issues detected.")
        print("=" * 72 + "\n")
        return False
    by_cwe = {}
    for f in findings:
        by_cwe.setdefault(f["cwe"], []).append(f)
    print("\nFINDINGS BY CWE:")
    print("-" * 72)
    for cwe, items in sorted(by_cwe.items(), key=lambda x: -len(x[1])):
        print("  " + cwe.ljust(12) + items[0]["vulnerability"][:40].ljust(42) + str(len(items)))
    if direct:
        print("\n" + "=" * 72)
        print("DIRECT VULNERABILITY PATTERNS")
        print("=" * 72)
        seen = set()
        shown = 0
        for f in sorted(direct, key=lambda x: 0 if x["severity"] == "CRITICAL" else 1):
            key = (os.path.basename(f["file"]), f["cwe"], f["line"])
            if key in seen:
                continue
            seen.add(key)
            print("\n  [" + f["severity"] + "] " + f["vulnerability"] + " (" + f["cwe"] + ")")
            print("  File   : " + os.path.relpath(f["file"], repo_path) + ":" + str(f["line"]))
            print("  OWASP  : " + f["owasp"])
            print("  Why    : " + f["why"])
            print("  Impact : " + f["impact"])
            print("  Code   : " + f["code"])
            shown += 1
            if shown >= 10:
                break
    if flows:
        print("\n" + "=" * 72)
        print("DATA-FLOW TAINT TRACES (source -> sink)")
        print("=" * 72)
        seen = set()
        shown = 0
        for f in sorted(flows, key=lambda x: (0 if x["severity"] == "CRITICAL" else 1, x["distance"])):
            key = (os.path.basename(f["file"]), f["cwe"])
            if key in seen:
                continue
            seen.add(key)
            print("\n  [" + f["severity"] + "] " + f["vulnerability"] + " (" + f["cwe"] + ")")
            print("  File       : " + os.path.relpath(f["file"], repo_path))
            print("  Confidence : " + f["confidence"] + " (" + str(f["distance"]) + " lines)")
            print("  SOURCE (line " + str(f["source_line"]) + "): " + f["source_code"])
            print("       |  no sanitization detected")
            print("       v")
            print("  SINK   (line " + str(f["sink_line"]) + "): " + f["sink_code"])
            shown += 1
            if shown >= 8:
                break
    print("\n" + "=" * 72)
    if crit:
        print("SAST VERDICT: CRITICAL vulnerabilities found.")
    elif high:
        print("SAST VERDICT: HIGH severity issues found.")
    print("=" * 72 + "\n")
    return bool(crit or high)

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print("Scanning: " + repo)
    findings, n = scan_directory(repo)
    blocked = print_report(findings, n, repo)
    sys.exit(1 if blocked else 0)
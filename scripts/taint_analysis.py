import os
import sys
import re

TAINT_SOURCES = {
    "python": [
        r"request\.(args|form|json|data|values|cookies|headers)",
        r"input\s*\(",
        r"sys\.argv",
        r"os\.environ\.get",
        r"flask\.request",
        r"\.get_json\s*\(",
    ],
    "java": [
        r"request\.getParameter",
        r"request\.getHeader",
        r"request\.getCookies",
        r"getQueryString",
        r"System\.getenv",
        r"Scanner\s*\(",
        r"\.getInputStream",
    ],
    "javascript": [
        r"req\.(body|query|params|cookies|headers)",
        r"location\.(search|hash|href)",
        r"document\.URL",
        r"window\.name",
        r"localStorage\.getItem",
        r"process\.argv",
    ],
    "php": [
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)",
        r"file_get_contents\s*\(\s*['\"]php://input",
    ]
}

DANGEROUS_SINKS = {
    "sql_injection": {
        "patterns": [
            r"execute\s*\(", r"executeQuery\s*\(", r"executeUpdate\s*\(",
            r"cursor\.execute", r"\.query\s*\(", r"createStatement",
            r"mysql_query", r"prepare\s*\(",
        ],
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "owasp": "A03:2021 Injection",
        "impact": "Full database read/write, credential theft, data exfiltration"
    },
    "command_injection": {
        "patterns": [
            r"os\.system\s*\(", r"subprocess\.(call|run|Popen|check_output)",
            r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder\s*\(",
            r"exec\s*\(", r"shell_exec", r"popen\s*\(", r"child_process",
        ],
        "cwe": "CWE-78",
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "owasp": "A03:2021 Injection",
        "impact": "Remote code execution, full server compromise"
    },
    "code_injection": {
        "patterns": [
            r"\beval\s*\(", r"\bexec\s*\(", r"Function\s*\(",
            r"setTimeout\s*\(\s*['\"]", r"pickle\.loads",
            r"yaml\.load\s*\(", r"ObjectInputStream",
        ],
        "cwe": "CWE-94",
        "name": "Code Injection",
        "severity": "CRITICAL",
        "owasp": "A03:2021 Injection",
        "impact": "Arbitrary code execution in application context"
    },
    "path_traversal": {
        "patterns": [
            r"open\s*\(", r"new\s+File\s*\(", r"FileInputStream\s*\(",
            r"readFile\s*\(", r"file_get_contents\s*\(",
            r"os\.path\.join", r"Paths\.get\s*\(",
        ],
        "cwe": "CWE-22",
        "name": "Path Traversal",
        "severity": "HIGH",
        "owasp": "A01:2021 Broken Access Control",
        "impact": "Read arbitrary files including /etc/passwd, config, keys"
    },
    "xss": {
        "patterns": [
            r"innerHTML\s*=", r"document\.write\s*\(",
            r"\.html\s*\(", r"dangerouslySetInnerHTML",
            r"response\.getWriter\(\)\.write", r"out\.print",
            r"render_template_string",
        ],
        "cwe": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "owasp": "A03:2021 Injection",
        "impact": "Session hijacking, credential theft, account takeover"
    },
    "ldap_injection": {
        "patterns": [r"search\s*\(.*filter", r"DirContext", r"ldap_search"],
        "cwe": "CWE-90",
        "name": "LDAP Injection",
        "severity": "HIGH",
        "owasp": "A03:2021 Injection",
        "impact": "Authentication bypass, directory enumeration"
    },
    "xxe": {
        "patterns": [
            r"DocumentBuilderFactory", r"SAXParserFactory",
            r"XMLReader", r"etree\.parse", r"minidom\.parse",
        ],
        "cwe": "CWE-611",
        "name": "XML External Entity (XXE)",
        "severity": "HIGH",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "File disclosure, SSRF, denial of service"
    },
    "ssrf": {
        "patterns": [
            r"requests\.(get|post)\s*\(", r"urllib\.request\.urlopen",
            r"HttpURLConnection", r"fetch\s*\(", r"axios\.",
            r"curl_exec", r"file_get_contents\s*\(\s*\$",
        ],
        "cwe": "CWE-918",
        "name": "Server-Side Request Forgery",
        "severity": "HIGH",
        "owasp": "A10:2021 SSRF",
        "impact": "Internal network access, cloud metadata theft (169.254.169.254)"
    },
    "deserialization": {
        "patterns": [
            r"pickle\.loads", r"ObjectInputStream", r"readObject\s*\(",
            r"yaml\.load\s*\(", r"unserialize\s*\(", r"JSON\.parse\s*\(",
        ],
        "cwe": "CWE-502",
        "name": "Insecure Deserialization",
        "severity": "CRITICAL",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "impact": "Remote code execution via crafted serialized objects"
    },
}

SANITIZERS = [
    r"escape\s*\(", r"sanitize", r"htmlspecialchars", r"quote\s*\(",
    r"parameterize", r"PreparedStatement", r"setString\s*\(",
    r"bindParam", r"re\.escape", r"shlex\.quote", r"validator\.",
    r"encodeURIComponent", r"DOMPurify", r"bleach\.clean",
]

EXT_LANG = {
    ".py": "python", ".java": "java", ".js": "javascript",
    ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".php": "php", ".rb": "python", ".go": "java",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor",
             "dist", "build", "target", "venv", ".venv", "test", "tests"}

def detect_language(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    return EXT_LANG.get(ext)

def find_taint_sources(content, lang):
    sources = []
    patterns = TAINT_SOURCES.get(lang, [])
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            sources.append({
                "line": line_num,
                "pattern": pattern,
                "text": match.group(0)
            })
    return sources

def find_sinks(content):
    sinks = []
    for sink_type, details in DANGEROUS_SINKS.items():
        for pattern in details["patterns"]:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                sinks.append({
                    "line": line_num,
                    "type": sink_type,
                    "cwe": details["cwe"],
                    "name": details["name"],
                    "severity": details["severity"],
                    "owasp": details["owasp"],
                    "impact": details["impact"],
                    "text": match.group(0)
                })
    return sinks

def has_sanitizer_between(content, start_line, end_line):
    lines = content.split("\n")
    segment = "\n".join(lines[max(0,start_line-1):end_line])
    for san in SANITIZERS:
        if re.search(san, segment):
            return True
    return False

def trace_taint_flow(filepath, content, lang):
    findings = []
    sources = find_taint_sources(content, lang)
    sinks = find_sinks(content)
    lines = content.split("\n")

    if not sources or not sinks:
        return findings

    for source in sources:
        for sink in sinks:
            distance = sink["line"] - source["line"]
            if 0 <= distance <= 40:
                sanitized = has_sanitizer_between(content, source["line"], sink["line"])
                confidence = "HIGH" if not sanitized and distance <= 15 else \
                             "MEDIUM" if not sanitized else "LOW"
                if sanitized:
                    continue
                source_code = lines[source["line"]-1].strip()[:80] if source["line"] <= len(lines) else ""
                sink_code = lines[sink["line"]-1].strip()[:80] if sink["line"] <= len(lines) else ""
                findings.append({
                    "file": filepath,
                    "vulnerability": sink["name"],
                    "cwe": sink["cwe"],
                    "owasp": sink["owasp"],
                    "severity": sink["severity"],
                    "confidence": confidence,
                    "impact": sink["impact"],
                    "source_line": source["line"],
                    "source_code": source_code,
                    "source_text": source["text"],
                    "sink_line": sink["line"],
                    "sink_code": sink_code,
                    "sink_text": sink["text"],
                    "flow_distance": distance,
                    "sanitized": sanitized
                })
    return findings

def scan_directory(repo_path):
    all_findings = []
    files_scanned = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            lang = detect_language(filepath)
            if not lang:
                continue
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                files_scanned += 1
                findings = trace_taint_flow(filepath, content, lang)
                all_findings.extend(findings)
            except Exception:
                pass
    return all_findings, files_scanned

def print_taint_report(findings, files_scanned, repo_path):
    print("\n" + "="*70)
    print("DATA-FLOW TAINT ANALYSIS ENGINE")
    print("Source-to-Sink Tracing | CWE + OWASP Top 10 Mapped")
    print("="*70)
    print(f"\nFiles analyzed      : {files_scanned}")
    print(f"Taint flows found   : {len(findings)}")
    print(f"Vulnerability types : {len(DANGEROUS_SINKS)} tracked")
    print(f"Sanitizers checked  : {len(SANITIZERS)} patterns")

    if not findings:
        print("\nNo unsanitized taint flows detected.")
        print("="*70 + "\n")
        return False

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    high_conf = [f for f in findings if f["confidence"] == "HIGH"]

    print(f"\nCRITICAL severity   : {len(critical)}")
    print(f"HIGH severity       : {len(high)}")
    print(f"HIGH confidence     : {len(high_conf)}")

    by_cwe = {}
    for f in findings:
        by_cwe.setdefault(f["cwe"], []).append(f)

    print(f"\nVULNERABILITIES BY CWE:")
    print("-"*70)
    for cwe, items in sorted(by_cwe.items(), key=lambda x: -len(x[1])):
        print(f"  {cwe:<12} {items[0]['vulnerability']:<35} {len(items)} flow(s)")

    print(f"\nTOP TAINT FLOWS (source -> sink):")
    print("="*70)

    shown = 0
    seen_files = set()
    for f in sorted(findings, key=lambda x: (
            {"CRITICAL":0,"HIGH":1,"MEDIUM":2}[x["severity"]],
            {"HIGH":0,"MEDIUM":1,"LOW":2}[x["confidence"]],
            x["flow_distance"])):
        key = (os.path.basename(f["file"]), f["cwe"])
        if key in seen_files:
            continue
        seen_files.add(key)
        rel = os.path.relpath(f["file"], repo_path)
        print(f"\n  [{f['severity']}] {f['vulnerability']} ({f['cwe']})")
        print(f"  File       : {rel}")
        print(f"  OWASP      : {f['owasp']}")
        print(f"  Confidence : {f['confidence']} (flow distance: {f['flow_distance']} lines)")
        print(f"  Impact     : {f['impact']}")
        print(f"  ")
        print(f"  SOURCE (line {f['source_line']}) - untrusted input enters:")
        print(f"     {f['source_code']}")
        print(f"  ")
        print(f"     |")
        print(f"     |  {f['flow_distance']} lines, NO SANITIZATION DETECTED")
        print(f"     v")
        print(f"  ")
        print(f"  SINK (line {f['sink_line']}) - dangerous operation:")
        print(f"     {f['sink_code']}")
        shown += 1
        if shown >= 12:
            break

    print("\n" + "="*70)
    if critical:
        print("TAINT VERDICT: CRITICAL - unsanitized user input reaches dangerous sinks.")
        print("Remote code execution or data breach is possible.")
    elif high:
        print("TAINT VERDICT: HIGH - unsanitized data flows detected.")
    print("="*70 + "\n")
    return len(critical) > 0 or len(high) > 0

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print(f"Starting taint analysis on: {repo_path}")
    findings, files_scanned = scan_directory(repo_path)
    blocked = print_taint_report(findings, files_scanned, repo_path)
    sys.exit(1 if blocked else 0)
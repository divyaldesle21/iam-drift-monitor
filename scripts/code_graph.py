import os
import sys
import json

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

# Each edge: having vuln A meaningfully enables reaching vuln B
EXPLOIT_EDGES = [
    ("CWE-79",  "CWE-384", "Stolen session cookie enables session fixation/hijack"),
    ("CWE-384", "CWE-89",  "Authenticated session reaches privileged SQL endpoints"),
    ("CWE-89",  "CWE-798", "Dumped DB rows expose stored credentials and API keys"),
    ("CWE-798", "CWE-918", "Recovered credentials authenticate internal service calls"),
    ("CWE-22",  "CWE-798", "Arbitrary file read exposes config files and secrets"),
    ("CWE-22",  "CWE-327", "Reading key material makes weak hashes crackable"),
    ("CWE-918", "CWE-798", "Cloud metadata endpoint returns IAM role credentials"),
    ("CWE-78",  "CWE-798", "Shell access reads environment variables and key files"),
    ("CWE-89",  "CWE-78",  "Stacked queries or xp_cmdshell escalate SQLi to OS commands"),
    ("CWE-502", "CWE-78",  "Deserialization gadget chain achieves command execution"),
    ("CWE-94",  "CWE-78",  "Code injection pivots to OS command execution"),
    ("CWE-611", "CWE-22",  "XXE external entity performs arbitrary file read"),
    ("CWE-611", "CWE-918", "XXE entity resolution triggers server-side requests"),
    ("CWE-327", "CWE-384", "Predictable/crackable tokens enable session forgery"),
]

CWE_META = {
    "CWE-89":  {"name": "SQL Injection",            "entry": True,  "impact": 10},
    "CWE-78":  {"name": "OS Command Injection",     "entry": True,  "impact": 10},
    "CWE-94":  {"name": "Code Injection",           "entry": True,  "impact": 10},
    "CWE-502": {"name": "Insecure Deserialization", "entry": True,  "impact": 9},
    "CWE-798": {"name": "Hardcoded Credentials",    "entry": False, "impact": 9},
    "CWE-918": {"name": "SSRF",                     "entry": True,  "impact": 8},
    "CWE-611": {"name": "XXE",                      "entry": True,  "impact": 7},
    "CWE-22":  {"name": "Path Traversal",           "entry": True,  "impact": 7},
    "CWE-79":  {"name": "Cross-Site Scripting",     "entry": True,  "impact": 6},
    "CWE-384": {"name": "Session Hijack",           "entry": False, "impact": 7},
    "CWE-327": {"name": "Weak Cryptographic Hash",  "entry": False, "impact": 5},
}

TERMINAL_GOALS = {
    "CWE-78":  "Remote code execution on the application server",
    "CWE-798": "Credential compromise enabling lateral movement",
    "CWE-918": "Cloud metadata access and IAM credential theft",
}

def load_findings(repo_path):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from taint_analysis import scan_directory
    findings, n = scan_directory(repo_path)
    present = {}
    for f in findings:
        present.setdefault(f["cwe"], []).append(f)
    return present, n

def build_graph(present_cwes):
    if HAS_NX:
        G = nx.DiGraph()
    else:
        G = None
    adj = {}
    edge_reasons = {}
    nodes = set(present_cwes.keys())
    for a, b, reason in EXPLOIT_EDGES:
        if a in nodes and b in nodes:
            adj.setdefault(a, []).append(b)
            edge_reasons[(a, b)] = reason
            if HAS_NX:
                G.add_edge(a, b, reason=reason)
    return G, adj, edge_reasons, nodes

def find_paths(adj, nodes, max_hops=4):
    paths = []
    def walk(node, trail):
        if len(trail) > max_hops:
            return
        nexts = adj.get(node, [])
        if not nexts and len(trail) >= 2:
            paths.append(list(trail))
            return
        terminal = node in TERMINAL_GOALS and len(trail) >= 2
        if terminal:
            paths.append(list(trail))
        for nxt in nexts:
            if nxt in trail:
                continue
            trail.append(nxt)
            walk(nxt, trail)
            trail.pop()
    for start in nodes:
        if CWE_META.get(start, {}).get("entry"):
            walk(start, [start])
    uniq = []
    seen = set()
    for p in sorted(paths, key=len, reverse=True):
        key = tuple(p)
        if key in seen:
            continue
        if any(key != o and set(key).issubset(set(o)) and len(o) > len(key) for o in seen):
            continue
        seen.add(key)
        uniq.append(p)
    return uniq

def score_path(path):
    return sum(CWE_META.get(c, {}).get("impact", 3) for c in path) + (len(path) - 1) * 5

def print_graph_report(present, paths, edge_reasons, n_files, repo_path):
    print("\n" + "=" * 72)
    print("CODE VULNERABILITY EXPLOIT GRAPH")
    print("Multi-Hop Attack Chain Analysis on Application Source Code")
    print("=" * 72)
    print("\nFiles analyzed        : " + str(n_files))
    print("Vulnerability classes : " + str(len(present)))
    print("Graph edges modeled   : " + str(len(EXPLOIT_EDGES)))
    print("Exploit paths found   : " + str(len(paths)))
    print("\nVULNERABILITY NODES PRESENT IN CODEBASE:")
    print("-" * 72)
    for cwe, items in sorted(present.items(), key=lambda x: -CWE_META.get(x[0], {}).get("impact", 0)):
        meta = CWE_META.get(cwe, {"name": "Unknown", "impact": 0, "entry": False})
        role = "entry point" if meta.get("entry") else "escalation node"
        print("  " + cwe.ljust(11) + meta["name"][:32].ljust(34) + str(len(items)).rjust(4) + " sites   " + role)
    if not paths:
        print("\nNo multi-hop exploit chains formed from the vulnerabilities present.")
        print("=" * 72 + "\n")
        return False
    print("\n" + "=" * 72)
    print("EXPLOIT CHAINS (entry point -> escalation -> objective)")
    print("=" * 72)
    ranked = sorted(paths, key=score_path, reverse=True)
    blocked = False
    for i, p in enumerate(ranked[:8], 1):
        sc = score_path(p)
        sev = "CRITICAL" if len(p) >= 3 or sc >= 25 else "HIGH"
        if sev == "CRITICAL":
            blocked = True
        print("\n  [" + sev + "] Chain " + str(i) + "  (" + str(len(p) - 1) + " hops, impact " + str(sc) + ")")
        chain_str = "  " + " -> ".join(CWE_META.get(c, {}).get("name", c) for c in p)
        print(chain_str)
        print("  " + " -> ".join(p))
        for a, b in zip(p, p[1:]):
            print("     " + a + " to " + b + ": " + edge_reasons.get((a, b), ""))
        goal = TERMINAL_GOALS.get(p[-1])
        if goal:
            print("     OBJECTIVE REACHED: " + goal)
        ex = present.get(p[0], [])
        if ex:
            f = ex[0]
            loc = os.path.relpath(f["file"], repo_path)
            line = f.get("line") or f.get("source_line") or "?"
            print("     Entry point in code: " + loc + ":" + str(line))
    print("\n" + "=" * 72)
    if blocked:
        print("GRAPH VERDICT: CRITICAL - multi-hop exploit chains are reachable")
        print("in this codebase. Individually moderate bugs combine into full compromise.")
    else:
        print("GRAPH VERDICT: exploit chains present but limited in depth.")
    print("=" * 72 + "\n")
    return blocked

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print("Building exploit graph for: " + repo)
    present, n = load_findings(repo)
    G, adj, reasons, nodes = build_graph(present)
    paths = find_paths(adj, nodes)
    blocked = print_graph_report(present, paths, reasons, n, repo)
    sys.exit(1 if blocked else 0)
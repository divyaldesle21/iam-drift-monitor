import json,sys,os,re,subprocess
from datetime import datetime
DANGEROUS_ACTIONS={"iam:PassRole","iam:CreateRole","iam:AttachRolePolicy","iam:CreatePolicyVersion","s3:DeleteBucket","s3:*","ec2:*","lambda:*","cloudtrail:StopLogging","cloudtrail:DeleteTrail","kms:Decrypt","secretsmanager:GetSecretValue","sts:AssumeRole","cloudwatch:*","*"}
def compute_risk_score(permissions):
    score=0
    for p in permissions:
        if p=="*": score+=30
        elif p in DANGEROUS_ACTIONS: score+=10
        else: score+=1
    return min(100,score)
def extract_permissions_from_content(content):
    permissions=set()
    for block in re.findall(r"\"Action\"\s*:\s*\[([^\]]+)\]",content): permissions.update(re.findall(r"\"([^\"]+)\"",block))
    permissions.update(re.findall(r"\"Action\"\s*:\s*\"([^\"]+)\"",content))
    for block in re.findall(r"actions\s*=\s*\[([^\]]+)\]",content): permissions.update(re.findall(r"\"([^\"]+)\"",block))
    return permissions
def get_git_log(repo_path,tf_file):
    try:
        result=subprocess.run(["git","log","--oneline","--follow",tf_file],cwd=repo_path,capture_output=True,text=True,timeout=30)
        commits=[]
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts=line.split(" ",1)
                if len(parts)==2: commits.append({"hash":parts[0],"message":parts[1]})
        return commits
    except: return []
def get_file_at_commit(repo_path,commit_hash,tf_file):
    try:
        result=subprocess.run(["git","show",f"{commit_hash}:{tf_file}"],cwd=repo_path,capture_output=True,text=True,timeout=10)
        return result.stdout if result.returncode==0 else ""
    except: return ""
def get_commit_info(repo_path,commit_hash,fmt):
    try:
        result=subprocess.run(["git","show","-s",f"--format={fmt}",commit_hash],cwd=repo_path,capture_output=True,text=True,timeout=10)
        return result.stdout.strip().split("\n")[0] if result.returncode==0 else "unknown"
    except: return "unknown"
def analyze_temporal_drift(repo_path,tf_file="infra/main.tf"):
    print(f"\nAnalyzing git history: {tf_file}")
    commits=get_git_log(repo_path,tf_file)
    if not commits:
        fp=os.path.join(repo_path,tf_file)
        if not os.path.exists(fp): return []
        with open(fp) as f: content=f.read()
        permissions=extract_permissions_from_content(content)
        risk=compute_risk_score(permissions)
        return [{"commit":"current","message":"Current state","date":datetime.now().strftime("%Y-%m-%d"),"author":"unknown","permissions":list(permissions),"new_permissions":list(permissions),"removed_permissions":[],"risk_score":risk,"score_delta":risk,"total_permissions":len(permissions)}]
    print(f"Found {len(commits)} commits\n")
    timeline=[]; prev_permissions=set(); prev_score=0
    for commit in reversed(commits):
        content=get_file_at_commit(repo_path,commit["hash"],tf_file)
        if not content: continue
        permissions=extract_permissions_from_content(content)
        risk=compute_risk_score(permissions)
        new_perms=permissions-prev_permissions; removed=prev_permissions-permissions
        timeline.append({"commit":commit["hash"],"message":commit["message"],"date":get_commit_info(repo_path,commit["hash"],"%ci"),"author":get_commit_info(repo_path,commit["hash"],"%an"),"permissions":list(permissions),"new_permissions":list(new_perms),"removed_permissions":list(removed),"risk_score":risk,"score_delta":risk-prev_score,"total_permissions":len(permissions)})
        prev_permissions=permissions; prev_score=risk
    return timeline
def detect_drift_patterns(timeline):
    alerts=[]
    if not timeline: return alerts
    scores=[t["risk_score"] for t in timeline]
    if len(scores)>=3 and scores[-1]-scores[0]>20: alerts.append({"type":"ACCELERATING_DRIFT","severity":"CRITICAL","message":f"Risk grew {scores[-1]-scores[0]} points over {len(timeline)} commits","recommendation":"Audit all recent IAM changes immediately"})
    for entry in timeline:
        if entry["score_delta"]>15: alerts.append({"type":"SPIKE","severity":"HIGH","commit":entry["commit"],"message":f"Risk spiked +{entry[\"score_delta\"]} in commit {entry[\"commit\"][:8]}","author":entry["author"],"new_permissions":entry["new_permissions"]})
        dangerous_new=[p for p in entry["new_permissions"] if p in DANGEROUS_ACTIONS]
        if dangerous_new: alerts.append({"type":"DANGEROUS_PERMISSION","severity":"HIGH","commit":entry["commit"],"author":entry["author"],"message":f"Dangerous permissions added: {chr(44).join(dangerous_new[:3])}","permissions":dangerous_new})
    if len(timeline)>=3 and all(timeline[i]["risk_score"]>=timeline[i-1]["risk_score"] for i in range(1,len(timeline))) and timeline[-1]["risk_score"]>30:
        alerts.append({"type":"SLOW_BURN_CREEP","severity":"CRITICAL","message":f"Continuous privilege growth across all {len(timeline)} commits","start_score":timeline[0]["risk_score"],"end_score":timeline[-1]["risk_score"],"recommendation":"Slow-burn creep pattern - no single commit looks dangerous but cumulative drift is critical"})
    return alerts
def print_temporal_report(timeline,alerts):
    print("\n"+"="*60); print("TEMPORAL PRIVILEGE DRIFT ANALYSIS"); print("Git History Mining | Slow-Burn Creep Detection"); print("="*60)
    if not timeline: print("No history found."); print("="*60+"\n"); return False
    print(f"\nCommits analyzed : {len(timeline)}\nTime span        : {timeline[0][\"date\"][:10]} to {timeline[-1][\"date\"][:10]}\nRisk progression : {timeline[0][\"risk_score\"]} -> {timeline[-1][\"risk_score\"]}")
    total_growth=timeline[-1]["risk_score"]-timeline[0]["risk_score"]
    if total_growth>0: print(f"Total drift      : +{total_growth} risk points")
    print(f"\nCOMMIT TIMELINE:\n"+"-"*60)
    for entry in timeline:
        score=entry["risk_score"]; delta=entry["score_delta"]
        bar="X"*(score//5)+"."*(20-score//5)
        delta_str=f"+{delta}" if delta>0 else str(delta)
        flag=" <-- SPIKE" if delta>15 else ""
        print(f"\n  Commit : {entry[\"commit\"][:8]} | {entry[\"date\"][:10]}\n  Author : {entry[\"author\"]}\n  Msg    : {entry[\"message\"][:50]}\n  Risk   : [{bar}] {score}/100 ({delta_str}){flag}\n  Perms  : {entry[\"total_permissions\"]} total")
        if entry["new_permissions"]:
            dangerous=[p for p in entry["new_permissions"] if p in DANGEROUS_ACTIONS]
            if dangerous: print(f"  ADDED  : {chr(44).join(dangerous[:3])} [DANGEROUS]")
            else: print(f"  ADDED  : {chr(44).join(list(entry[\"new_permissions\"])[:3])}")
    if alerts:
        print(f"\n{\"=\"*60}\nDRIFT ALERTS ({len(alerts)}):\n{\"=\"*60}")
        for alert in alerts:
            print(f"\n  [{alert[\"severity\"]}] {alert[\"type\"]}\n  {alert[\"message\"]}")
            if "recommendation" in alert: print(f"  Rec: {alert[\"recommendation\"]}")
            if "author" in alert: print(f"  Author: {alert[\"author\"]}")
    print("\n"+"="*60)
    blocked=any(a["severity"]=="CRITICAL" for a in alerts)
    if blocked: print("TEMPORAL VERDICT: CRITICAL drift detected. Slow-burn creep identified.")
    elif alerts: print("TEMPORAL VERDICT: Drift detected. Review recommended.")
    else: print("TEMPORAL VERDICT: No significant drift.")
    print("="*60+"\n"); return blocked
if __name__=="__main__":
    repo_path=sys.argv[1] if len(sys.argv)>1 else "/app"
    tf_file=sys.argv[2] if len(sys.argv)>2 else "infra/main.tf"
    timeline=analyze_temporal_drift(repo_path,tf_file)
    alerts=detect_drift_patterns(timeline)
    blocked=print_temporal_report(timeline,alerts)
    sys.exit(1 if blocked else 0)
import json,sys,os
CANARY_PERMISSIONS={"iam:CreateVirtualMFADevice":{"reason":"No CI/CD pipeline needs MFA device creation","threat":"Attacker creating MFA to lock out users","mitre":"T1098","severity":"CRITICAL"},"iam:DeactivateMFADevice":{"reason":"MFA deactivation should never be automated","threat":"Attacker disabling MFA for account takeover","mitre":"T1556","severity":"CRITICAL"},"iam:DeleteAccountPasswordPolicy":{"reason":"Password policy deletion has no automation use","threat":"Attacker weakening account security","mitre":"T1556","severity":"CRITICAL"},"ec2:GetPasswordData":{"reason":"Windows password decryption not needed in deploy roles","threat":"Attacker stealing Windows admin credentials","mitre":"T1552","severity":"CRITICAL"},"sts:GetFederationToken":{"reason":"Federation tokens enable long-lived credential abuse","threat":"Attacker generating persistent credentials","mitre":"T1550","severity":"CRITICAL"},"iam:DeleteVirtualMFADevice":{"reason":"MFA device deletion should never be automated","threat":"Attacker removing MFA protection","mitre":"T1098","severity":"CRITICAL"},"organizations:LeaveOrganization":{"reason":"Leaving AWS Organizations removes security controls","threat":"Attacker isolating account from guardrails","mitre":"T1562","severity":"CRITICAL"},"support:CreateCase":{"reason":"Support cases in deploy roles indicate social engineering","threat":"Attacker using AWS support for manipulation","mitre":"T1199","severity":"HIGH"},"iam:UpdateAccountPasswordPolicy":{"reason":"Account password policy changes are administrative only","threat":"Attacker weakening password requirements","mitre":"T1110","severity":"HIGH"},"aws-portal:ModifyBilling":{"reason":"Billing modification has no infrastructure use case","threat":"Financial manipulation or resource abuse","mitre":"T1496","severity":"HIGH"}}
def analyze_honeypot(plan_path):
    with open(plan_path) as f: plan=json.load(f)
    all_findings=[]
    for change in plan.get("resource_changes",[]):
        if "aws_iam" not in change.get("type",""): continue
        if not set(change.get("change",{}).get("actions",[])) & {"create","update"}: continue
        after=change.get("change",{}).get("after") or {}
        policy_str=after.get("policy") or after.get("assume_role_policy")
        if not policy_str: continue
        try: policy=json.loads(policy_str) if isinstance(policy_str,str) else policy_str
        except: continue
        for stmt in policy.get("Statement",[]):
            if stmt.get("Effect")!="Allow": continue
            acts=stmt.get("Action",[])
            if isinstance(acts,str): acts=[acts]
            if "*" in acts:
                for action,details in CANARY_PERMISSIONS.items():
                    f=details.copy(); f["action"]=action; f["resource"]=change.get("address","unknown"); f["trigger"]="wildcard_includes_canary"
                    all_findings.append(f)
                break
            for action in acts:
                if action in CANARY_PERMISSIONS:
                    f=CANARY_PERMISSIONS[action].copy(); f["action"]=action; f["resource"]=change.get("address","unknown"); f["trigger"]="direct_match"
                    all_findings.append(f)
    return all_findings
def print_honeypot_report(findings):
    print("\n"+"="*60); print("HONEYPOT PERMISSION LAYER"); print("Canary-Based Deception Detection | Zero False Positives"); print("="*60)
    print(f"\nCanary permissions monitored : {len(CANARY_PERMISSIONS)}")
    if not findings: print("No canary permissions triggered."); print("="*60+"\n"); return False
    print(f"Canary triggers detected     : {len(findings)}\n\nTHREAT DETECTIONS:"); print("-"*60)
    blocked=False; seen=set()
    for f in findings:
        if f["action"] in seen: continue
        seen.add(f["action"])
        print(f"\n  [{f[\"severity\"]}] CANARY TRIGGERED: {f[\"action\"]}\n  Resource : {f.get(\"resource\",\"unknown\")}\n  Reason   : {f[\"reason\"]}\n  Threat   : {f[\"threat\"]}\n  MITRE    : {f[\"mitre\"]}")
        if f["severity"]=="CRITICAL": blocked=True
    print("\n"+"="*60)
    if blocked: print("HONEYPOT VERDICT: CRITICAL canary triggered.\nPossible insider threat or attacker-modified policy.")
    else: print("HONEYPOT VERDICT: Non-critical canary. Review recommended.")
    print("="*60+"\n"); return blocked
if __name__=="__main__":
    plan_path=sys.argv[1] if len(sys.argv)>1 else "/app/plan.json"
    findings=analyze_honeypot(plan_path); blocked=print_honeypot_report(findings); sys.exit(1 if blocked else 0)
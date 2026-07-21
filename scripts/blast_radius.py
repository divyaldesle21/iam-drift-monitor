import json,sys,os
CAPABILITY_MAP={"iam:PassRole":{"capability":"role_hijacking","impact":"Assume any IAM role","severity":10},"iam:CreateRole":{"capability":"role_creation","impact":"Create new IAM roles","severity":9},"iam:AttachRolePolicy":{"capability":"policy_attachment","impact":"Attach any policy to any role","severity":9},"iam:CreatePolicyVersion":{"capability":"policy_replacement","impact":"Replace policies with malicious versions","severity":9},"iam:CreateAccessKey":{"capability":"credential_theft","impact":"Create backdoor credentials","severity":10},"iam:CreateUser":{"capability":"backdoor_user","impact":"Create backdoor IAM users","severity":9},"ec2:*":{"capability":"full_compute","impact":"Full EC2 control","severity":9},"ec2:RunInstances":{"capability":"compute_hijack","impact":"Launch EC2 for crypto mining","severity":7},"lambda:*":{"capability":"full_serverless","impact":"Full Lambda control","severity":9},"lambda:CreateFunction":{"capability":"serverless_exec","impact":"Deploy arbitrary Lambda code","severity":8},"s3:*":{"capability":"full_s3","impact":"Full S3 read write delete","severity":9},"s3:DeleteBucket":{"capability":"data_destruction","impact":"Delete S3 buckets permanently","severity":9},"cloudwatch:*":{"capability":"full_monitoring","impact":"Delete all CloudWatch alarms and logs","severity":8},"cloudtrail:StopLogging":{"capability":"audit_evasion","impact":"Disable CloudTrail audit trail","severity":10},"cloudtrail:DeleteTrail":{"capability":"audit_destruction","impact":"Delete audit trail permanently","severity":10},"secretsmanager:GetSecretValue":{"capability":"secret_theft","impact":"Exfiltrate all secrets","severity":9},"kms:Decrypt":{"capability":"decrypt_data","impact":"Decrypt any KMS data","severity":8},"sts:AssumeRole":{"capability":"lateral_movement","impact":"Move laterally across accounts","severity":8}}
ATTACK_CHAINS=[{"name":"Full Data Exfiltration","required":["s3:*"],"description":"Read copy delete all S3 data","mitre":"T1530","severity":"CRITICAL"},{"name":"Compute Takeover","required":["ec2:*"],"description":"Launch crypto miners and C2","mitre":"T1578","severity":"CRITICAL"},{"name":"Monitoring Blind Spot","required":["cloudwatch:*"],"description":"Delete all alarms and logs","mitre":"T1562","severity":"HIGH"},{"name":"Audit Destruction","required":["cloudtrail:StopLogging","cloudtrail:DeleteTrail"],"description":"Stop then delete audit trail","mitre":"T1562.008","severity":"CRITICAL"},{"name":"Serverless Backdoor","required":["lambda:*","iam:PassRole"],"description":"Create Lambda with admin role","mitre":"T1648","severity":"CRITICAL"},{"name":"Exfiltrate Cover Tracks","required":["s3:*","cloudwatch:*"],"description":"Exfiltrate data then delete logs","mitre":"T1530","severity":"CRITICAL"},{"name":"Serverless Compute Pivot","required":["lambda:*","ec2:*"],"description":"Lambda to EC2 lateral movement","mitre":"T1648","severity":"HIGH"},{"name":"Full Account Takeover","required":["iam:PassRole","sts:AssumeRole"],"description":"Chain role assumptions for full access","mitre":"T1548","severity":"CRITICAL"}]
def extract_permissions(plan_path):
    with open(plan_path) as f: plan=json.load(f)
    permissions=set()
    for change in plan.get("resource_changes",[]):
        if "aws_iam" not in change.get("type",""): continue
        if not set(change.get("change",{}).get("actions",[])) & {"create","update"}: continue
        after=change.get("change",{}).get("after") or {}
        policy_str=after.get("policy") or after.get("assume_role_policy")
        if not policy_str: continue
        try:
            policy=json.loads(policy_str) if isinstance(policy_str,str) else policy_str
        except: continue
        for stmt in policy.get("Statement",[]):
            if stmt.get("Effect")!="Allow": continue
            acts=stmt.get("Action",[])
            if isinstance(acts,str): acts=[acts]
            permissions.update(acts)
    return permissions
def simulate_blast_radius(permissions):
    capabilities=[]
    total_severity=0
    for perm in permissions:
        if perm in CAPABILITY_MAP:
            cap=CAPABILITY_MAP[perm].copy(); cap["permission"]=perm
            capabilities.append(cap); total_severity+=cap["severity"]
    active_chains=[c for c in ATTACK_CHAINS if all(r in permissions for r in c["required"])]
    blast_score=min(100,(total_severity*3)+(len(active_chains)*10))
    categories={"account_takeover":[c for c in capabilities if "role" in c["capability"] or "lateral" in c["capability"]],"data_exfiltration":[c for c in capabilities if "data" in c["capability"] or "secret" in c["capability"] or "s3" in c["capability"]],"defense_evasion":[c for c in capabilities if "evasion" in c["capability"] or "destruction" in c["capability"] or "monitoring" in c["capability"]],"execution":[c for c in capabilities if "exec" in c["capability"] or "compute" in c["capability"] or "serverless" in c["capability"]]}
    return {"permissions_analyzed":list(permissions),"capabilities":capabilities,"attack_chains":active_chains,"categories":categories,"blast_score":blast_score}
def print_blast_report(result):
    score=result["blast_score"]; chains=result["attack_chains"]; cats=result["categories"]; caps=result["capabilities"]
    level="CATASTROPHIC -- Full account compromise likely" if score>=80 else "CRITICAL -- Severe damage possible" if score>=60 else "HIGH -- Significant damage possible" if score>=40 else "LOW -- Minimal impact"
    bar="X"*(score//5)+"."*(20-score//5)
    print("\n"+"="*60); print("BLAST RADIUS SIMULATION"); print("="*60)
    print(f"Blast Score  : [{bar}] {score}/100"); print(f"Threat Level : {level}")
    print(f"Permissions  : {len(result[\"permissions_analyzed\"])} analyzed"); print(f"Capabilities : {len(caps)} unlocked"); print(f"Attack Chains: {len(chains)} possible")
    if cats["account_takeover"]: print(f"\n[ACCOUNT TAKEOVER ({len(cats[\"account_takeover\"])}):]"); [print(f"   {c[\"permission\"]} --> {c[\"impact\"]}") for c in cats["account_takeover"]]
    if cats["data_exfiltration"]: print(f"\n[DATA EXFILTRATION ({len(cats[\"data_exfiltration\"])}):]"); [print(f"   {c[\"permission\"]} --> {c[\"impact\"]}") for c in cats["data_exfiltration"]]
    if cats["defense_evasion"]: print(f"\n[DEFENSE EVASION ({len(cats[\"defense_evasion\"])}):]"); [print(f"   {c[\"permission\"]} --> {c[\"impact\"]}") for c in cats["defense_evasion"]]
    if cats["execution"]: print(f"\n[CODE EXECUTION ({len(cats[\"execution\"])}):]"); [print(f"   {c[\"permission\"]} --> {c[\"impact\"]}") for c in cats["execution"]]
    if chains:
        print(f"\n[ACTIVE ATTACK CHAINS ({len(chains)}):]")
        for chain in chains: print(f"\n   [{chain[\"severity\"]}] {chain[\"name\"]}\n   Attack  : {chain[\"description\"]}\n   MITRE   : {chain[\"mitre\"]}\n   Requires: {\" + \".join(chain[\"required\"])}")
    print("\n"+"="*60); print(f"BLAST RADIUS VERDICT: {level}"); print("="*60+"\n")
    return score>=40
if __name__=="__main__":
    plan_path=sys.argv[1] if len(sys.argv)>1 else "/app/plan.json"
    permissions=extract_permissions(plan_path); result=simulate_blast_radius(permissions)
    blocked=print_blast_report(result); sys.exit(1 if blocked else 0)
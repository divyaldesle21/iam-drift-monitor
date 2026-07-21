import json,sys,os
CODON_TABLE={"iam:PassRole":"AAA","iam:CreateRole":"AAC","iam:AttachRolePolicy":"AAG","iam:PutRolePolicy":"AAT","iam:CreatePolicyVersion":"ACA","iam:SetDefaultPolicyVersion":"ACC","iam:CreateUser":"ACG","iam:CreateAccessKey":"ACT","s3:GetObject":"CCA","s3:PutObject":"CCC","s3:DeleteBucket":"CCG","s3:DeleteObject":"CCT","s3:ListBucket":"CGC","s3:*":"CGG","ec2:RunInstances":"GGA","ec2:*":"GGG","ec2:DescribeInstances":"GGT","lambda:CreateFunction":"TTA","lambda:InvokeFunction":"TTC","lambda:*":"TTG","cloudtrail:StopLogging":"TAA","cloudtrail:DeleteTrail":"TAC","kms:Decrypt":"ATA","secretsmanager:GetSecretValue":"ATC","ssm:GetParameter":"ATG","sts:AssumeRole":"GAA","cloudwatch:*":"GTA","cloudwatch:DeleteAlarms":"GTG","*":"TGG"}
MALICIOUS_GENOMES=[{"id":"GENOME_001","name":"Classic Privilege Escalation","mitre":"T1548","source":"Pacu iam__privesc_scan","sequence":"AAA-AAC-AAG-ACA-ACC","description":"PassRole CreateRole AttachPolicy chain"},{"id":"GENOME_002","name":"Full Admin Takeover","mitre":"T1078","source":"AWS Security Blog","sequence":"TGG-GGG-CGG-TTG-GTA","description":"Wildcard action full admin equivalent"},{"id":"GENOME_003","name":"Serverless Backdoor","mitre":"T1648","source":"Rhino Security Labs","sequence":"TTA-TTC-AAA-GAA","description":"Lambda creation with PassRole"},{"id":"GENOME_004","name":"Data Exfiltration","mitre":"T1530","source":"MITRE ATT&CK Cloud Matrix","sequence":"CGG-CCG-CCA-CCC","description":"Full S3 data exfiltration"},{"id":"GENOME_005","name":"Audit Evasion","mitre":"T1562.008","source":"MITRE ATT&CK T1562","sequence":"TAA-TAC-GTA-GTG","description":"CloudTrail destruction and evasion"},{"id":"GENOME_006","name":"Credential Harvesting","mitre":"T1552","source":"AWS reInforce 2023","sequence":"ATC-ATA-ATG","description":"Secrets KMS SSM credential access"},{"id":"GENOME_007","name":"Compute Hijacking","mitre":"T1578","source":"MITRE ATT&CK T1578","sequence":"GGG-GGA","description":"Full EC2 control crypto mining C2"}]
def policy_to_dna(actions):
    if isinstance(actions,str): actions=[actions]
    codons=[CODON_TABLE.get(a,f"N{abs(hash(a))%100:02d}") for a in sorted(actions)]
    return "-".join(codons)
def smith_waterman_score(seq1,seq2):
    c1=seq1.split("-"); c2=seq2.split("-")
    if not c1 or not c2: return 0
    rows=len(c1)+1; cols=len(c2)+1; matrix=[[0]*cols for _ in range(rows)]
    match_score=3; mismatch=-1; gap=-2; max_score=0
    for i in range(1,rows):
        for j in range(1,cols):
            match=matrix[i-1][j-1]+(match_score if c1[i-1]==c2[j-1] else mismatch)
            delete=matrix[i-1][j]+gap; insert=matrix[i][j-1]+gap
            matrix[i][j]=max(0,match,delete,insert); max_score=max(max_score,matrix[i][j])
    max_possible=match_score*min(len(c1),len(c2))
    return 0 if max_possible==0 else min(100,int((max_score/max_possible)*100))
def scan_plan_dna(plan_path):
    with open(plan_path) as f: plan=json.load(f)
    all_results=[]
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
            dna_seq=policy_to_dna(acts)
            matches=[{"genome_id":g["id"],"genome_name":g["name"],"mitre":g["mitre"],"source":g["source"],"similarity":smith_waterman_score(dna_seq,g["sequence"]),"description":g["description"],"genome_dna":g["sequence"],"severity":"CRITICAL" if smith_waterman_score(dna_seq,g["sequence"])>=70 else "HIGH" if smith_waterman_score(dna_seq,g["sequence"])>=40 else "MEDIUM"} for g in MALICIOUS_GENOMES if smith_waterman_score(dna_seq,g["sequence"])>0]
            if matches:
                matches.sort(key=lambda x:x["similarity"],reverse=True)
                all_results.append({"resource":change.get("address","unknown"),"actions":acts,"dna_sequence":dna_seq,"genome_matches":matches})
    return all_results
def print_dna_report(results):
    print("\n"+"="*60); print("POLICY DNA BIOINFORMATICS ENGINE"); print("Smith-Waterman Sequence Alignment | MITRE ATT&CK Mapped"); print("="*60)
    if not results: print("No malicious genome matches."); print("="*60+"\n"); return False
    blocked=False; total=sum(len(r["genome_matches"]) for r in results)
    print(f"\nPolicies analyzed : {len(results)}\nGenome matches    : {total}\nKnown genomes     : {len(MALICIOUS_GENOMES)}")
    for r in results:
        print(f"\nRESOURCE: {r[\"resource\"]}\nPOLICY DNA: {r[\"dna_sequence\"]}\nACTIONS  : {chr(44).join(r[\"actions\"][:4])}")
        for m in r["genome_matches"][:3]:
            bar="X"*(m["similarity"]//10)+"."*(10-m["similarity"]//10)
            print(f"\n  [{m[\"severity\"]}] {m[\"genome_name\"]}\n  Similarity : [{bar}] {m[\"similarity\"]}%\n  MITRE      : {m[\"mitre\"]}\n  Source     : {m[\"source\"]}\n  Genome DNA : {m[\"genome_dna\"]}")
            if m["severity"] in ("CRITICAL","HIGH"): blocked=True
    print("\n"+"="*60)
    if blocked: print("DNA VERDICT: Policy matches known malicious genome patterns.")
    else: print("DNA VERDICT: No critical genome matches found.")
    print("="*60+"\n"); return blocked
if __name__=="__main__":
    plan_path=sys.argv[1] if len(sys.argv)>1 else "/app/plan.json"
    results=scan_plan_dna(plan_path); blocked=print_dna_report(results); sys.exit(1 if blocked else 0)
import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    
    iam = boto3.client('iam')
    
    report = {
        "report_title": "MFA Compliance Check",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "framework_references": ["ISO 27001 A.8.5", "NIST SP 800-53 IA-2", "SOC 2 CC6.1"],
        "summary": {},
        "findings": []
    }
    
    users = iam.list_users()['Users']
    
    total_users = len(users)
    compliant = 0
    non_compliant = 0
    
    for user in users:
        username = user['UserName']
        created = user['CreateDate'].strftime("%Y-%m-%d")
        
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        
        if mfa_devices:
            compliant += 1
        else:
            non_compliant += 1
            
            login_profile = None
            try:
                login_profile = iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                pass
            
            severity = "HIGH" if login_profile else "MEDIUM"
            
            if login_profile:
                recommendation = f"Enable MFA for user {username} immediately. Console access without MFA represents a critical authentication control gap."
            else:
                recommendation = f"Enable MFA for user {username}. This service account lacks MFA — if credentials are compromised, API access to AWS resources is unprotected."
            
            report["findings"].append({
                "finding_id": f"MFA-{non_compliant:03d}",
                "severity": severity,
                "user": username,
                "created_date": created,
                "has_console_access": login_profile is not None,
                "mfa_enabled": False,
                "control_reference": "ISO 27001 A.8.5 / NIST IA-2 / SOC 2 CC6.1",
                "recommendation": recommendation
            })
    
    compliance_rate = round((compliant / total_users * 100), 1) if total_users > 0 else 0
    
    report["summary"] = {
        "total_users": total_users,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": f"{compliance_rate}%",
        "overall_status": "PASS" if non_compliant == 0 else "FAIL"
    }
    
    print(json.dumps(report, indent=2))
    
    return {
        "statusCode": 200,
        "body": json.dumps(report, indent=2)
    }

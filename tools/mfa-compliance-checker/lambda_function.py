import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    ses = boto3.client('ses')
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    file_timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    BUCKET = 'grc-audit-reports-465352048537'

    # Parametros opcionales de entrada
    send_email = event.get('send_email', False)
    email_to = event.get('email_to', None)
    sender_email = event.get('sender_email', None)

    report = {
        "report_title": "MFA Compliance Check",
        "generated_at": timestamp,
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

    # Guardar reporte en S3
    s3_key = f"mfa-compliance-checker/{file_timestamp}.json"
    s3.put_object(
        Bucket=BUCKET,
        Key=s3_key,
        Body=json.dumps(report, indent=2),
        ContentType='application/json'
    )
    report["s3_report_saved"] = f"s3://{BUCKET}/{s3_key}"

    # Enviar email si se solicita
    if send_email and email_to and sender_email:
        high_count = sum(1 for f in report["findings"] if f["severity"] == "HIGH")
        medium_count = sum(1 for f in report["findings"] if f["severity"] == "MEDIUM")

        findings_list = ""
        for f in report["findings"]:
            findings_list += f"\n  [{f['severity']}] {f['user']} — {'Console access, no MFA' if f['has_console_access'] else 'Service account, no MFA'}"

        email_body = (
            f"MFA Compliance Check\n"
            f"Generated: {timestamp}\n\n"
            f"SUMMARY\n"
            f"-------\n"
            f"Total Users     : {total_users}\n"
            f"Compliant       : {compliant}\n"
            f"Non-Compliant   : {non_compliant}\n"
            f"Compliance Rate : {compliance_rate}%\n"
            f"Overall Status  : {'PASS' if non_compliant == 0 else 'FAIL'}\n"
            f"High Findings   : {high_count}\n"
            f"Medium Findings : {medium_count}\n\n"
            f"FINDINGS\n"
            f"--------"
            f"{findings_list if findings_list else chr(10) + '  No findings - all users compliant.'}\n\n"
            f"FULL REPORT\n"
            f"-----------\n"
            f"s3://{BUCKET}/{s3_key}\n\n"
            f"---\n"
            f"GRC Automation Toolkit | MFA Compliance Checker\n"
            f"Control References: ISO 27001 A.8.5 / NIST IA-2 / SOC 2 CC6.1\n"
        )

        ses.send_email(
            Source=sender_email,
            Destination={'ToAddresses': [email_to]},
            Message={
                'Subject': {
                    'Data': f"MFA Compliance Report - {file_timestamp}",
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': email_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        report["email_sent_to"] = email_to

    print(json.dumps(report, indent=2))
    
    return {
        "statusCode": 200,
        "body": json.dumps(report, indent=2)
    }

import boto3
import json
from datetime import datetime

def lambda_handler(event, context):

    rds = boto3.client('rds')
    s3 = boto3.client('s3')
    ses = boto3.client('ses')
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    file_timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    BUCKET = 'grc-audit-reports-465352048537'
    MINIMUM_RETENTION_DAYS = 7
    MINIMUM_RETENTION_WARNING = 3

    # Parametros opcionales de entrada
    send_email = event.get('send_email', False)
    email_to = event.get('email_to', None)
    sender_email = event.get('sender_email', None)

    findings = []
    instances_evaluated = 0
    compliant_count = 0

    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:

            instance_id = db['DBInstanceIdentifier']
            engine = db['Engine']
            retention = db.get('BackupRetentionPeriod', 0)
            encrypted = db.get('StorageEncrypted', False)
            backup_window = db.get('PreferredBackupWindow', 'not set')
            status = db.get('DBInstanceStatus', 'unknown')

            instances_evaluated += 1
            instance_findings = []

            # Finding 1: Backups deshabilitados
            if retention == 0:
                instance_findings.append({
                    "finding_id": f"RDS-BACKUP-001-{instance_id}",
                    "title": "Automated Backups Disabled",
                    "severity": "CRITICAL",
                    "detail": f"Instance '{instance_id}' has automated backups completely disabled (retention period = 0). No point-in-time recovery is possible.",
                    "control_reference": "ISO 27001 A.8.13 / NIST SP 800-53 CP-9 / SOC 2 CC9.1",
                    "remediation": "Enable automated backups with a minimum retention period of 7 days. Navigate to RDS > Modify Instance > Backup > Set retention period to 7 or more days."
                })

            # Finding 2: Retencion insuficiente
            elif retention < MINIMUM_RETENTION_DAYS:
                severity = "HIGH" if retention < MINIMUM_RETENTION_WARNING else "MEDIUM"
                instance_findings.append({
                    "finding_id": f"RDS-BACKUP-002-{instance_id}",
                    "title": "Backup Retention Period Below Policy Minimum",
                    "severity": severity,
                    "detail": f"Instance '{instance_id}' has a backup retention period of {retention} day(s). Minimum required is {MINIMUM_RETENTION_DAYS} days. Current configuration limits point-in-time recovery to the last {retention} day(s) only.",
                    "control_reference": "ISO 27001 A.8.13 / NIST SP 800-53 CP-9 / SOC 2 CC9.1",
                    "remediation": f"Increase backup retention period to at least {MINIMUM_RETENTION_DAYS} days. Navigate to RDS > Modify Instance > Backup > Set retention period to 7 or more days."
                })

            # Finding 3: Sin encriptacion
            if not encrypted:
                instance_findings.append({
                    "finding_id": f"RDS-BACKUP-003-{instance_id}",
                    "title": "RDS Instance Storage Not Encrypted",
                    "severity": "HIGH",
                    "detail": f"Instance '{instance_id}' storage is not encrypted. Backup snapshots generated from unencrypted instances are also unencrypted, exposing data at rest.",
                    "control_reference": "ISO 27001 A.8.24 / NIST SP 800-53 SC-28 / SOC 2 CC6.7",
                    "remediation": "Encryption cannot be enabled on an existing RDS instance directly. Create an encrypted snapshot, restore it as a new encrypted instance, and decommission the unencrypted instance."
                })

            if not instance_findings:
                compliant_count += 1

            findings.append({
                "instance_id": instance_id,
                "engine": engine,
                "status": status,
                "backup_retention_days": retention,
                "storage_encrypted": encrypted,
                "backup_window": backup_window,
                "compliance_status": "COMPLIANT" if not instance_findings else "NON-COMPLIANT",
                "findings": instance_findings
            })

    # Contar findings por severidad
    all_findings = [f for inst in findings for f in inst["findings"]]
    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    # Guardar reporte en S3
    s3_key = f"rds-backup-checker/{file_timestamp}.json"
    report = {
        "report_title": "RDS Backup Compliance Assessment",
        "generated_at": timestamp,
        "scope": "All RDS instances in current AWS account and region",
        "policy_standard": f"Minimum backup retention: {MINIMUM_RETENTION_DAYS} days | Encryption: Required",
        "summary": {
            "instances_evaluated": instances_evaluated,
            "compliant": compliant_count,
            "non_compliant": instances_evaluated - compliant_count,
            "total_findings": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count
        },
        "instances": findings,
        "framework_references": {
            "ISO_27001": "A.8.13 Information backup, A.8.24 Use of cryptography",
            "NIST_SP_800_53": "CP-9 System Backup, SC-28 Protection of Information at Rest",
            "SOC_2": "CC9.1 Risk Mitigation, CC6.7 Transmission and Encryption"
        },
        "s3_report_saved": f"s3://{BUCKET}/{s3_key}"
    }

    s3.put_object(
        Bucket=BUCKET,
        Key=s3_key,
        Body=json.dumps(report, indent=2),
        ContentType='application/json'
    )

    # Enviar email si se solicita
    if send_email and email_to and sender_email:
        non_compliant_list = ""
        for inst in findings:
            if inst["compliance_status"] == "NON-COMPLIANT":
                for f in inst["findings"]:
                    non_compliant_list += f"\n  [{f['severity']}] {inst['instance_id']} - {f['title']}"

        email_body = (
            f"RDS Backup Compliance Assessment\n"
            f"Generated: {timestamp}\n\n"
            f"SUMMARY\n"
            f"-------\n"
            f"Instances Evaluated : {instances_evaluated}\n"
            f"Compliant           : {compliant_count}\n"
            f"Non-Compliant       : {instances_evaluated - compliant_count}\n"
            f"Critical Findings   : {critical_count}\n"
            f"High Findings       : {high_count}\n"
            f"Medium Findings     : {medium_count}\n\n"
            f"FINDINGS\n"
            f"--------"
            f"{non_compliant_list if non_compliant_list else chr(10) + '  No findings - all instances compliant.'}\n\n"
            f"FULL REPORT\n"
            f"-----------\n"
            f"s3://{BUCKET}/{s3_key}\n\n"
            f"---\n"
            f"GRC Automation Toolkit | RDS Backup Compliance Checker\n"
            f"Control References: ISO 27001 A.8.13 / NIST CP-9 / SOC 2 CC9.1\n"
        )

        ses.send_email(
            Source=sender_email,
            Destination={'ToAddresses': [email_to]},
            Message={
                'Subject': {
                    'Data': f"RDS Backup Compliance Report - {file_timestamp}",
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
        'statusCode': 200,
        'body': json.dumps(report, indent=2)
    }

# RDS Backup Compliance Checker

AWS Lambda function that audits all RDS instances in an account for backup configuration compliance. Generates a structured JSON report with control references, severity classifications, and remediation recommendations — ready for audit evidence packages.

## What It Detects

| Finding ID | Title | Severity | Control Reference |
|---|---|---|---|
| RDS-BACKUP-001 | Automated Backups Disabled | CRITICAL | ISO 27001 A.8.13 / NIST CP-9 / SOC 2 CC9.1 |
| RDS-BACKUP-002 | Backup Retention Period Below Policy Minimum | HIGH / MEDIUM | ISO 27001 A.8.13 / NIST CP-9 / SOC 2 CC9.1 |
| RDS-BACKUP-003 | RDS Instance Storage Not Encrypted | HIGH | ISO 27001 A.8.24 / NIST SC-28 / SOC 2 CC6.7 |

Policy minimum: **7 days** retention. Instances with retention between 1-2 days are classified HIGH. Instances with retention between 3-6 days are classified MEDIUM.

## Report Output

Each execution saves a timestamped JSON report to S3 and optionally sends an executive summary by email.

**S3 path:** `s3://<your-bucket>/rds-backup-checker/YYYY-MM-DD_HH-MM-SS.json`

**Report structure:**
```json
{
  "report_title": "RDS Backup Compliance Assessment",
  "generated_at": "2026-03-19 14:09:20 UTC",
  "summary": {
    "instances_evaluated": 2,
    "compliant": 0,
    "non_compliant": 2,
    "critical": 1,
    "high": 1,
    "medium": 0
  },
  "instances": [...],
  "framework_references": {...}
}
```

## Prerequisites

### 1. Create the S3 bucket
Create an S3 bucket to store audit reports. Update the `BUCKET` variable in the code with your bucket name:
```python
BUCKET = 'your-bucket-name'
```

### 2. Deploy the Lambda function
- Runtime: **Python 3.11**
- Handler: `lambda_function.lambda_handler`
- Timeout: **30 seconds** (default 3s is insufficient)
- Memory: 128 MB (default)

### 3. Attach IAM policies to the Lambda execution role
- `AmazonRDSReadOnlyAccess`
- `AmazonS3FullAccess`
- `AmazonSESFullAccess` *(only required if using email delivery)*

### 4. Verify sender email in SES *(optional — email delivery only)*
If you want email delivery, verify your sender address in AWS SES:
- Go to **SES → Verified identities → Create identity**
- Select **Email address** and verify ownership
- Note: new SES accounts operate in sandbox mode — both sender and recipient must be verified

## Usage

### Basic execution (report to S3 only)
```json
{}
```

### With email delivery
```json
{
  "send_email": true,
  "sender_email": "your-verified-address@example.com",
  "email_to": "recipient@example.com"
}
```

## Architecture Note

This tool is part of the [GRC Automation Toolkit](https://github.com/cjmolinac/GRC-Portfolio). All tools write reports to a centralized S3 audit evidence bucket, organized by tool name and timestamp — mirroring how mature GRC programs consolidate audit evidence under consistent retention policies.

## Framework Mapping

| Framework | Control | Requirement |
|---|---|---|
| ISO 27001:2022 | A.8.13 | Information backup |
| ISO 27001:2022 | A.8.24 | Use of cryptography |
| NIST SP 800-53 | CP-9 | System Backup |
| NIST SP 800-53 | SC-28 | Protection of Information at Rest |
| SOC 2 | CC9.1 | Risk Mitigation |
| SOC 2 | CC6.7 | Transmission and Encryption |

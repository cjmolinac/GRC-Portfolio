# MFA Compliance Checker

**Framework References:** ISO 27001 A.8.5 | NIST SP 800-53 IA-2 | SOC 2 CC6.1  
**Platform:** AWS Lambda (Python 3.11) + S3 + SES  
**Author:** Carlos J. Molina — GRC Analyst & ISO 27001 Lead Auditor

---

## The Problem This Solves

One of the most common findings in SOC 2 and ISO 27001 audits is users with console access and no MFA enabled. This represents a critical authentication control gap — a compromised password is all an attacker needs to access the entire AWS environment.

Manual reviews are slow, inconsistent, and easy to skip. This tool automates the detection, saves a timestamped report to S3 for audit evidence, and optionally delivers a summary by email.

---

## What It Does

This AWS Lambda function:

1. Connects to AWS IAM and retrieves all users in the account
2. Checks each user for MFA device registration
3. Distinguishes between human users (console access) and service accounts (API only)
4. Classifies findings by severity — HIGH for console users, MEDIUM for service accounts
5. Generates a structured audit report with control references and remediation recommendations
6. Saves a timestamped JSON report to S3 for audit evidence
7. Optionally sends an executive summary by email via SES

---

## Sample Output

```json
{
  "report_title": "MFA Compliance Check",
  "generated_at": "2026-03-23 13:24:10 UTC",
  "framework_references": ["ISO 27001 A.8.5", "NIST SP 800-53 IA-2", "SOC 2 CC6.1"],
  "summary": {
    "total_users": 5,
    "compliant": 0,
    "non_compliant": 5,
    "compliance_rate": "0.0%",
    "overall_status": "FAIL"
  },
  "findings": [
    {
      "finding_id": "MFA-001",
      "severity": "HIGH",
      "user": "admin-no-mfa",
      "has_console_access": true,
      "mfa_enabled": false,
      "control_reference": "ISO 27001 A.8.5 / NIST IA-2 / SOC 2 CC6.1",
      "recommendation": "Enable MFA for user admin-no-mfa immediately. Console access without MFA represents a critical authentication control gap."
    },
    {
      "finding_id": "MFA-004",
      "severity": "MEDIUM",
      "user": "service-account-api",
      "has_console_access": false,
      "mfa_enabled": false,
      "control_reference": "ISO 27001 A.8.5 / NIST IA-2 / SOC 2 CC6.1",
      "recommendation": "Enable MFA for user service-account-api. This service account lacks MFA — if credentials are compromised, API access to AWS resources is unprotected."
    }
  ],
  "s3_report_saved": "s3://grc-audit-reports-<your-account-id>/mfa-compliance-checker/2026-03-23_13-24-10.json",
  "email_sent_to": "recipient@example.com"
}
```

---

## Severity Logic

| Condition | Severity | Rationale |
|---|---|---|
| No MFA + Console access | HIGH | Human user — password compromise = full console access |
| No MFA + No console access | MEDIUM | Service account — API credentials exposed but no console risk |
| MFA enabled | COMPLIANT | Control satisfied |

---

## Sample Events

**Basic execution (report to S3 only):**
```json
{}
```

**With email delivery:**
```json
{
  "send_email": true,
  "sender_email": "your-verified-address@example.com",
  "email_to": "recipient@example.com"
}
```

---

## Deployment

1. **Create an S3 bucket** for audit reports — e.g. `grc-audit-reports-<your-account-id>`. Update the `BUCKET` variable in the code with your bucket name.

2. **Create a new AWS Lambda function:**
   - Runtime: Python 3.11
   - Timeout: 30 seconds
   - Memory: 128 MB (default)

3. **Attach the following policies to the execution role:**
   - `IAMReadOnlyAccess`
   - `AmazonS3FullAccess`
   - `AmazonSESFullAccess` *(only required if using email delivery)*

4. **Verify sender email in SES** *(optional — email delivery only):*
   - Go to **SES → Verified identities → Create identity**
   - Select **Email address** and verify ownership
   - Note: new SES accounts operate in sandbox mode — both sender and recipient must be verified

5. **Paste the code** from `lambda_function.py` and deploy.

---

## GRC Context

This tool automates evidence collection for the following controls:

| Framework | Control | Requirement |
|---|---|---|
| ISO 27001:2022 | A.8.5 | Secure authentication |
| NIST SP 800-53 | IA-2 | Identification and Authentication |
| SOC 2 | CC6.1 | Logical access security — authentication mechanisms |

In a production environment this function would be scheduled via EventBridge to run weekly, with findings delivered to a compliance dashboard or ticketing system for remediation tracking.

---

## Part of the GRC Automation Toolkit

This is the first tool in an incremental GRC automation portfolio designed to automate evidence collection for the most common audit findings across SOC 2, ISO 27001, and NIST CSF.

**Next:** [Access Lifecycle Manager](../access-lifecycle-manager/) — SOC 2 CC6.2  
**Also available:** [RDS Backup Compliance Checker](../rds-backup-checker/) — SOC 2 CC9.1

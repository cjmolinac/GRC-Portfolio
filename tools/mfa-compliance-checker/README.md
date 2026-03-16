# MFA Compliance Checker

**Framework References:** ISO 27001 A.8.5 | NIST SP 800-53 IA-2 | SOC 2 CC6.1  
**Platform:** AWS Lambda (Python 3.11)  
**Author:** Carlos J. Molina — GRC Analyst & ISO 27001 Lead Auditor

---

## The Problem This Solves

One of the most common findings in SOC 2 and ISO 27001 audits is users with console access and no MFA enabled. This represents a critical authentication control gap — a compromised password is all an attacker needs to access the entire AWS environment.

Manual reviews are slow, inconsistent, and easy to skip. This tool automates the detection and documents findings in a format ready for audit evidence packages.

---

## What It Does

This AWS Lambda function:

1. Connects to AWS IAM and retrieves all users in the account
2. Checks each user for MFA device registration
3. Distinguishes between human users (console access) and service accounts (API only)
4. Classifies findings by severity — HIGH for console users, MEDIUM for service accounts
5. Generates a structured audit report with control references and remediation recommendations

---

## Sample Output
```json
{
  "report_title": "MFA Compliance Check",
  "generated_at": "2026-03-16 15:42:33 UTC",
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
  ]
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

## Deployment

1. Create a new AWS Lambda function (Python 3.11)
2. Attach the `IAMReadOnlyAccess` managed policy to the execution role
3. Paste the code from `lambda_function.py`
4. Deploy and run — no additional configuration required

---

## GRC Context

This tool automates evidence collection for the following controls:

- **ISO 27001 A.8.5** — Secure authentication
- **NIST SP 800-53 IA-2** — Identification and Authentication
- **SOC 2 CC6.1** — Logical access security — authentication mechanisms

In a production environment this function would be scheduled via EventBridge to run weekly, with findings delivered to a compliance dashboard or ticketing system for remediation tracking.

---

## Part of the GRC Automation Toolkit

This is the first tool in an incremental GRC automation portfolio designed to automate evidence collection for the most common audit findings across SOC 2, ISO 27001, and NIST CSF.

**Coming next:** CloudTrail Change Auditor (SOC 2 CC8.1) — detecting unauthorized changes to AWS infrastructure.

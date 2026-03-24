# Access Lifecycle Manager

**Framework References:** ISO 27001 A.5.18 | NIST SP 800-53 AC-2 | SOC 2 CC6.2  
**Platform:** AWS Lambda (Python 3.11) + S3 + SES  
**Author:** Carlos J. Molina — GRC Analyst & ISO 27001 Lead Auditor

---

## The Problem This Solves

One of the most persistent findings in access management audits is accounts that remain active after an employee leaves, changes roles, or goes on leave. The process breakdown is always the same: HR notifies IT, IT processes when available, nobody verifies, nobody documents. The access stays active.

This tool automates the entire access lifecycle — suspension, reactivation, and termination — with a complete audit trail stored in S3 and optional email delivery to the requesting team.

---

## What It Does

Three actions, one function:

**SUSPEND** — Disables console access and API keys, saves the user's complete previous state to S3 for later restoration. Used for vacations, leave, or temporary separation.

**REACTIVATE** — Reads the saved state from S3, restores console access, API keys, and attached policies exactly as they were. Deletes the suspension record once complete.

**TERMINATE** — Permanently removes console access, deactivates all API keys, and detaches all policies. No state saved — this action is irreversible.

---

## Sample Events

**Suspend:**
```json
{
  "username": "analyst-no-mfa",
  "action": "suspend",
  "reason": "Annual leave 2026-03-20 to 2026-03-27",
  "requested_by": "hr-manager"
}
```

**Suspend with email confirmation:**
```json
{
  "username": "analyst-no-mfa",
  "action": "suspend",
  "reason": "Annual leave 2026-03-20 to 2026-03-27",
  "requested_by": "hr-manager",
  "send_email": true,
  "sender_email": "your-verified-address@example.com",
  "email_to": "recipient@example.com"
}
```

**Reactivate:**
```json
{
  "username": "analyst-no-mfa",
  "action": "reactivate",
  "reason": "Return from annual leave",
  "requested_by": "hr-manager"
}
```

**Terminate:**
```json
{
  "username": "test-user-no-mfa",
  "action": "terminate",
  "reason": "Employment terminated 2026-03-17",
  "requested_by": "hr-director"
}
```

---

## Audit Trail

Every action generates a structured JSON log saved to two locations:

**1. Centralized audit bucket** — All actions are logged to the shared GRC audit evidence bucket:
```
s3://grc-audit-reports-<your-account-id>/access-lifecycle-manager/YYYY-MM-DD_HH-MM-SS_action_username.json
```
The filename includes the action and username, making the audit history readable without opening each file.

**2. Lifecycle state bucket** — For SUSPEND actions only, the user's previous state is saved for exact restoration:
```
s3://grc-access-lifecycle-states/suspended/username.json
```

**Sample audit log:**
```json
{
  "action": "SUSPEND",
  "username": "analyst-no-mfa",
  "timestamp": "2026-03-24 14:27:56 UTC",
  "requested_by": "hr-manager",
  "reason": "Annual leave 2026-03-20 to 2026-03-27",
  "actions_taken": [
    "Console access suspended",
    "Previous state saved to S3: suspended/analyst-no-mfa.json"
  ],
  "control_reference": "ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2",
  "status": "COMPLETED",
  "audit_log_saved": "s3://grc-audit-reports-465352048537/access-lifecycle-manager/2026-03-24_14-27-56_suspend_analyst-no-mfa.json"
}
```

---

## Deployment

### Prerequisites

1. **Create two S3 buckets:**
   - `grc-access-lifecycle-states` — stores suspension state files
   - `grc-audit-reports-<your-account-id>` — centralized audit evidence bucket (shared with other toolkit tools). Update the `BUCKET_AUDIT` variable in the code with your bucket name.

2. **Create a Lambda function:**
   - Runtime: Python 3.11
   - Timeout: 30 seconds
   - Memory: 128 MB (default)

3. **Attach the following policies to the execution role:**
   - `IAMFullAccess`
   - `AmazonS3FullAccess`
   - `AmazonSESFullAccess` *(only required if using email delivery)*

4. **Verify sender email in SES** *(optional — email delivery only):*
   - Go to **SES → Verified identities → Create identity**
   - Select **Email address** and verify ownership
   - Note: new SES accounts operate in sandbox mode — both sender and recipient must be verified

5. **Paste the code** from `lambda_function.py` and deploy.

> **Note on permissions:** This implementation uses broad managed policies for lab simplicity. In production, IAM, S3, and SES permissions would be replaced with custom least-privilege policies scoped to the minimum required actions.

---

## GRC Context

| Framework | Control | Requirement |
|---|---|---|
| ISO 27001:2022 | A.5.18 | Access rights management |
| NIST SP 800-53 | AC-2 | Account management |
| SOC 2 | CC6.2 | Prior to issuing system credentials and access |

---

## Part of the GRC Automation Toolkit

**Previous:** [MFA Compliance Checker](../mfa-compliance-checker/) — SOC 2 CC6.1  
**Next:** [RDS Backup Compliance Checker](../rds-backup-checker/) — SOC 2 CC9.1

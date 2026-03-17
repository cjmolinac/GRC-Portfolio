# Access Lifecycle Manager

**Framework References:** ISO 27001 A.5.18 | NIST SP 800-53 AC-2 | SOC 2 CC6.2  
**Platform:** AWS Lambda (Python 3.11) + S3  
**Author:** Carlos J. Molina — GRC Analyst & ISO 27001 Lead Auditor

---

## The Problem This Solves

One of the most persistent findings in access management audits is accounts that remain active after an employee leaves, changes roles, or goes on leave. The process breakdown is always the same: HR notifies IT, IT processes when available, nobody verifies, nobody documents. The access stays active.

This tool automates the entire access lifecycle — suspension, reactivation, and termination — with a complete audit trail stored in S3.

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

Every action generates a structured log in CloudWatch and, for suspensions, a state file in S3:
```json
{
  "action": "SUSPEND",
  "username": "analyst-no-mfa",
  "timestamp": "2026-03-17 15:49:07 UTC",
  "requested_by": "hr-manager",
  "reason": "Annual leave 2026-03-20 to 2026-03-27",
  "actions_taken": [
    "Console access suspended",
    "Previous state saved to S3: suspended/analyst-no-mfa.json"
  ],
  "control_reference": "ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2",
  "status": "COMPLETED"
}
```

---

## Deployment

1. Create an S3 bucket named `grc-access-lifecycle-states`
2. Create a Lambda function (Python 3.11, 30s timeout)
3. Attach `IAMFullAccess` and `AmazonS3FullAccess` to the execution role
4. Paste the code from `lambda_function.py` and deploy

**Note on permissions:** This implementation uses broad managed policies for lab simplicity. In production, both IAM and S3 permissions would be replaced with custom least-privilege policies scoped to the minimum required actions. A production-ready policy is planned as a follow-up in the GRC Automation Toolkit roadmap.

---

## GRC Context

- **ISO 27001 A.5.18** — Access rights management
- **NIST SP 800-53 AC-2** — Account management
- **SOC 2 CC6.2** — Prior to issuing system credentials and access

---

## Part of the GRC Automation Toolkit

**Previous:** MFA Compliance Checker (SOC 2 CC6.1)  
**Next:** CloudTrail Change Auditor (SOC 2 CC8.1)

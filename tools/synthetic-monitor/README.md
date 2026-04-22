# Synthetic Monitoring Tool

**Framework References:** SOC 2 A1.1 | SOC 2 A1.2 | SOC 2 CC8.1 | NIST SP 800-53 AU-12 | ISO 27001 A.12.1  
**Platform:** AWS Lambda (Python 3.11) + InfluxDB Cloud + Grafana  
**Author:** Carlos J. Molina — GRC Analyst & ISO 27001 Lead Auditor

---

## The Problem This Solves

Availability and security posture are audit evidence — not just operational metrics. Organizations that rely on manual checks or basic uptime monitoring cannot demonstrate continuous compliance with availability controls, cannot detect unauthorized content changes, and have no audit trail when something goes wrong.

This tool runs automatically on a schedule and generates continuous, structured evidence that a system was monitored, what its security posture was, and whether any anomalies were detected — ready for audit evidence packages.

---

## What It Does

This AWS Lambda function monitors target URLs and generates structured audit evidence on every run:

1. **Availability check** — verifies the site is up and returns HTTP 200
2. **Latency measurement** — response time and TTFB classified as OK / WARNING / CRITICAL
3. **SSL certificate validation** — verifies certificate validity, days remaining until expiry, issuer, and TLS version
4. **Security header audit** — checks for required headers mapped to ISO 27001, NIST, and SOC 2 controls
5. **Content integrity verification** — SHA-256 hash of page content compared against last known state
6. **Unauthorized change detection** — correlates content hash changes with GitHub commit history to distinguish authorized deployments from unexpected modifications
7. **Deduplicated alerting** — sends email alerts via SES only on state transitions, not on every run
8. **Audit evidence** — saves timestamped JSON reports to S3 and metrics to InfluxDB for Grafana dashboards

---

## Sample Output

```json
{
  "report_title": "Synthetic Monitoring Run",
  "generated_at": "2026-04-21T15:33:31.000Z",
  "framework_references": ["SOC 2 A1.1", "SOC 2 A1.2", "SOC 2 CC8.1", "NIST SP 800-53 AU-12", "ISO 27001 A.12.1"],
  "sites": [
    {
      "name": "grc_portfolio",
      "url": "https://d38tr29xjy4yu5.cloudfront.net",
      "is_up": 1,
      "response_time_ms": 198.37,
      "ssl_valid": 1,
      "ssl_days_remaining": 141,
      "ssl_expiry_date": "2026-09-09T12:00:00+00:00",
      "ssl_issuer": "Amazon",
      "ssl_tls_version": "TLSv1.3",
      "ssl_expiring_soon": false,
      "missing_headers": 2,
      "hash_changed": 0,
      "unauthorized_change": 0
    }
  ]
}
```

---

## Alert Types

| Alert | Severity | Trigger |
|---|---|---|
| Site Down | CRITICAL | HTTP status != 200 or connection failure |
| SSL Invalid | CRITICAL | Certificate validation failed |
| SSL Expiring Soon | WARNING | Certificate expires within 30 days |
| High Latency | CRITICAL | Response time exceeds LATENCY_CRITICAL_MS |
| Elevated Latency | WARNING | Response time exceeds LATENCY_WARNING_MS |
| Unauthorized Content Change | CRITICAL | Hash changed with no new GitHub commit |
| Missing Portfolio Elements | WARNING | Expected content not found in page |
| Critical Security Headers Missing | WARNING | HSTS or other critical headers absent |

All alerts are deduplicated — email is sent only when state transitions from OK to alert, not on every check.

---

## Security Header Audit

| Header | Severity | Framework References |
|---|---|---|
| Strict-Transport-Security | CRITICAL | ISO 27001 A.8.24 / NIST SC-8 / SOC 2 CC6.1 |
| Content-Security-Policy | HIGH | ISO 27001 A.8.24 / NIST SI-3 / SOC 2 CC6.8 |
| X-Frame-Options | HIGH | ISO 27001 A.8.24 / NIST SC-18 / SOC 2 CC6.8 |
| X-Content-Type-Options | MEDIUM | ISO 27001 A.8.24 / NIST SI-3 / SOC 2 CC6.8 |
| Referrer-Policy | MEDIUM | ISO 27001 A.8.24 / NIST SC-8 / SOC 2 CC6.1 |
| Permissions-Policy | LOW | ISO 27001 A.8.24 / NIST AC-3 / SOC 2 CC6.3 |

---

## Deployment

### Prerequisites

1. **InfluxDB Cloud account** — free tier available at influxdata.com. Create a bucket named `website-monitoring`.

2. **Grafana Cloud account** — free tier available at grafana.com. Connect your InfluxDB bucket as a data source.

3. **S3 bucket** for audit reports — `grc-audit-reports-<your-account-id>`. Update the `S3_BUCKET` environment variable.

4. **SES verified email** — verify sender and recipient addresses in AWS SES. Note: new accounts operate in sandbox mode.

5. **GitHub repository** — the tool correlates content hash changes with your GitHub commit history to detect unauthorized modifications.

### Lambda Configuration

- Runtime: **Python 3.11**
- Timeout: **30 seconds**
- Memory: **128 MB**
- Trigger: **EventBridge Schedule** — recommended every 60 minutes

### IAM Policies Required

- `AmazonS3FullAccess` — scoped to audit reports bucket
- `AmazonSESFullAccess` — for alert email delivery

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| INFLUXDB_URL | InfluxDB Cloud endpoint | — |
| INFLUXDB_ORG | InfluxDB organization name | — |
| INFLUXDB_BUCKET | InfluxDB bucket name | website-monitoring |
| INFLUXDB_TOKEN | InfluxDB authentication token | — |
| SES_SENDER | Verified SES sender email | — |
| ALERT_RECIPIENT | Alert destination email | — |
| S3_BUCKET | Audit reports S3 bucket | — |
| GITHUB_REPO | GitHub repo (owner/repo format) | — |
| LATENCY_WARNING_MS | Warning threshold in ms | 300 |
| LATENCY_CRITICAL_MS | Critical threshold in ms | 800 |
| SSL_EXPIRY_WARNING_DAYS | Days before expiry to trigger warning | 30 |

### Dependencies

This tool requires the following Python packages — deploy as a Lambda Layer or include in your deployment package:

```
requests
beautifulsoup4
```

The `ssl`, `socket`, `json`, `os`, `time`, `hashlib`, and `datetime` modules are part of the Python standard library and require no installation.

---

## GRC Context

| Framework | Control | Requirement |
|---|---|---|
| SOC 2 | A1.1 | Availability — capacity management and monitoring |
| SOC 2 | A1.2 | Availability — environmental controls |
| SOC 2 | CC8.1 | Change management — unauthorized change detection |
| NIST SP 800-53 | AU-12 | Audit record generation |
| ISO 27001:2022 | A.12.1 | Operational procedures and responsibilities |

---

## Third-Party Monitoring Authorization
This tool is designed for deployment in third-party risk management contexts — not only for monitoring your own infrastructure, but for continuously verifying the external security posture of vendors and service providers.
A contract template is included in the /legal directory. It formalizes the Client's right to monitor, defines the Monitored Surface, specifies Provider obligations (including non-interference and change notification), and establishes the audit evidence framework — including the IAM permissions and technical parameters required to operate this tool.
Most vendor contracts include generic audit clauses ("the client may verify compliance") without defining what verification means technically. This template closes that gap by translating monitoring parameters directly into contractual obligations.

---

## Part of the GRC Automation Toolkit

**Also available:**
- [MFA Compliance Checker](../mfa-compliance-checker/) — SOC 2 CC6.1
- [Access Lifecycle Manager](../access-lifecycle-manager/) — SOC 2 CC6.2
- [RDS Backup Compliance Checker](../rds-backup-checker/) — SOC 2 CC9.1

"""
Synthetic Monitoring Lambda - GRC Portfolio Monitor
Monitors portfolio and reference URLs with:
- Availability, latency, SSL validation and certificate details
- Security header audit mapped to GRC frameworks
- Content integrity verification vs last known deployment
- GitHub commit correlation for unauthorized change detection
- Multi-tier alerting via SES
- Audit evidence saved to S3

Environment Variables Required:
    INFLUXDB_URL        - InfluxDB Cloud endpoint
    INFLUXDB_ORG        - InfluxDB organization name
    INFLUXDB_BUCKET     - InfluxDB bucket name
    INFLUXDB_TOKEN      - InfluxDB authentication token
    SES_SENDER          - Verified SES sender email
    ALERT_RECIPIENT     - Alert destination email
    S3_BUCKET           - Audit reports S3 bucket
    GITHUB_REPO         - GitHub repo in format owner/repo (e.g. cjmolinac/GRC-Portfolio)
    LATENCY_WARNING_MS  - Warning threshold in ms (default 300)
    LATENCY_CRITICAL_MS - Critical threshold in ms (default 800)
    SSL_EXPIRY_WARNING_DAYS - Days before expiry to trigger warning (default 30)
"""

import json
import os
import ssl
import socket
import time
import hashlib
import boto3
import requests
from datetime import datetime, timezone
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Configuration from environment variables
# ---------------------------------------------------------------------------
INFLUXDB_URL    = os.environ.get("INFLUXDB_URL", "https://us-east-1-1.aws.cloud2.influxdata.com")
INFLUXDB_ORG    = os.environ.get("INFLUXDB_ORG", "Monitoring")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "website-monitoring")
INFLUXDB_TOKEN  = os.environ.get("INFLUXDB_TOKEN", "")

SES_SENDER      = os.environ.get("SES_SENDER", "datacjmolinac@gmail.com")
ALERT_RECIPIENT = os.environ.get("ALERT_RECIPIENT", "datacjmolinac@gmail.com")
S3_BUCKET       = os.environ.get("S3_BUCKET", "grc-audit-reports-465352048537")
GITHUB_REPO     = os.environ.get("GITHUB_REPO", "cjmolinac/GRC-Portfolio")

LATENCY_WARNING_MS  = int(os.environ.get("LATENCY_WARNING_MS",  "300"))
LATENCY_CRITICAL_MS = int(os.environ.get("LATENCY_CRITICAL_MS", "800"))
SSL_EXPIRY_WARNING_DAYS = int(os.environ.get("SSL_EXPIRY_WARNING_DAYS", "30"))

TIMEOUT = 10

# ---------------------------------------------------------------------------
# Websites to monitor
# ---------------------------------------------------------------------------
WEBSITES = [
    {
        "url":  "https://d38tr29xjy4yu5.cloudfront.net",
        "name": "grc_portfolio",
        "type": "portfolio",
        "check_content": True,
        "expected_elements": [
            "Carlos Molina GRC Professional",
            "GRC Automation Toolkit",
            "Case Studies",
            "github.com/cjmolinac"
        ]
    },
    {
        "url":  "https://www.google.com",
        "name": "reference_google",
        "type": "reference",
        "check_content": False,
        "expected_elements": []
    }
]

# ---------------------------------------------------------------------------
# Security headers mapped to GRC frameworks
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security":    {"severity": "CRITICAL", "frameworks": ["ISO 27001 A.8.24", "NIST SC-8",  "SOC 2 CC6.1"]},
    "Content-Security-Policy":      {"severity": "HIGH",     "frameworks": ["ISO 27001 A.8.24", "NIST SI-3",  "SOC 2 CC6.8"]},
    "X-Frame-Options":              {"severity": "HIGH",     "frameworks": ["ISO 27001 A.8.24", "NIST SC-18", "SOC 2 CC6.8"]},
    "X-Content-Type-Options":       {"severity": "MEDIUM",   "frameworks": ["ISO 27001 A.8.24", "NIST SI-3",  "SOC 2 CC6.8"]},
    "Referrer-Policy":              {"severity": "MEDIUM",   "frameworks": ["ISO 27001 A.8.24", "NIST SC-8",  "SOC 2 CC6.1"]},
    "Permissions-Policy":           {"severity": "LOW",      "frameworks": ["ISO 27001 A.8.24", "NIST AC-3",  "SOC 2 CC6.3"]},
}

# ---------------------------------------------------------------------------
# AWS clients
# ---------------------------------------------------------------------------
s3_client  = boto3.client("s3")
ses_client = boto3.client("ses", region_name="us-east-1")


# ---------------------------------------------------------------------------
# SSL Certificate checker
# ---------------------------------------------------------------------------
def check_ssl_certificate(url: str) -> dict:
    """
    Extract SSL certificate details using Python's native ssl library.
    No external API or dependencies required.
    Returns certificate validity, expiry date, days remaining, issuer, and TLS version.
    """
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(TIMEOUT)
            s.connect((hostname, 443))
            cert        = s.getpeercert()
            tls_version = s.version()

        expiry_str     = cert["notAfter"]
        expiry_dt      = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

        issuer  = dict(x[0] for x in cert.get("issuer",  [])).get("organizationName", "Unknown")
        subject = dict(x[0] for x in cert.get("subject", [])).get("commonName", hostname)

        return {
            "valid":           True,
            "days_remaining":  days_remaining,
            "expiry_date":     expiry_dt.isoformat(),
            "issuer":          issuer,
            "subject":         subject,
            "tls_version":     tls_version,
            "expiring_soon":   days_remaining <= SSL_EXPIRY_WARNING_DAYS,
            "error":           None
        }

    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "days_remaining": 0, "expiry_date": None,
                "issuer": None, "subject": None, "tls_version": None,
                "expiring_soon": False, "error": f"Certificate verification failed: {str(e)[:120]}"}

    except ssl.SSLError as e:
        return {"valid": False, "days_remaining": 0, "expiry_date": None,
                "issuer": None, "subject": None, "tls_version": None,
                "expiring_soon": False, "error": f"SSL error: {str(e)[:120]}"}

    except Exception as e:
        return {"valid": False, "days_remaining": 0, "expiry_date": None,
                "issuer": None, "subject": None, "tls_version": None,
                "expiring_soon": False, "error": f"Error: {str(e)[:120]}"}


# ---------------------------------------------------------------------------
# GitHub: get latest commit on main
# ---------------------------------------------------------------------------
def get_latest_github_commit(repo: str) -> dict:
    """Fetch latest commit SHA and timestamp from GitHub API."""
    try:
        url  = f"https://api.github.com/repos/{repo}/commits/main"
        resp = requests.get(url, timeout=5, headers={"Accept": "application/vnd.github.v3+json"})
        if resp.status_code == 200:
            data = resp.json()
            return {
                "sha":       data["sha"][:12],
                "message":   data["commit"]["message"][:100],
                "timestamp": data["commit"]["author"]["date"]
            }
    except Exception as e:
        print(f"GitHub API error: {e}")
    return {}


# ---------------------------------------------------------------------------
# S3: load / save last known content hash
# ---------------------------------------------------------------------------
def load_last_state(site_name: str):
    key = f"synthetic-monitor/content-hashes/{site_name}.json"
    try:
        obj  = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        data = json.loads(obj["Body"].read())
        return {
            "hash":       data.get("hash"),
            "commit_sha": data.get("commit", {}).get("sha")
        }
    except Exception:
        return None


def save_current_hash(site_name: str, content_hash: str, commit_info: dict):
    key     = f"synthetic-monitor/content-hashes/{site_name}.json"
    payload = {
        "hash":     content_hash,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "commit":   commit_info
    }
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET, Key=key,
            Body=json.dumps(payload, indent=2),
            ContentType="application/json"
        )
    except Exception as e:
        print(f"Error saving hash for {site_name}: {e}")


def load_alert_state(site_name: str) -> dict:
    key = f"synthetic-monitor/alert-state/{site_name}.json"
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        return json.loads(obj["Body"].read())
    except Exception:
        return {}


def save_alert_state(site_name: str, state: dict):
    key = f"synthetic-monitor/alert-state/{site_name}.json"
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET, Key=key,
            Body=json.dumps(state, indent=2),
            ContentType="application/json"
        )
    except Exception as e:
        print(f"Error saving alert state for {site_name}: {e}")


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------
def check_website(site: dict, commit_info: dict) -> dict:
    url            = site["url"]
    name           = site["name"]
    endpoint_type  = site["type"]
    check_content  = site.get("check_content", False)
    expected_elems = site.get("expected_elements", [])

    metrics = {
        "url":                    url,
        "name":                   name,
        "type":                   endpoint_type,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "status_code":            0,
        "response_time_ms":       0,
        "ttfb_ms":                0,
        "response_size_bytes":    0,
        "is_up":                  0,
        "ssl_valid":              0,
        "ssl_days_remaining":     0,
        "ssl_expiry_date":        None,
        "ssl_issuer":             None,
        "ssl_tls_version":        None,
        "ssl_expiring_soon":      False,
        "ssl_error":              None,
        "latency_status":         "ok",
        "missing_headers":        0,
        "header_findings":        [],
        "content_hash":           None,
        "hash_changed":           0,
        "unauthorized_change":    0,
        "missing_elements":       [],
        "error":                  None
    }

    # SSL certificate check — independent of HTTP request
    ssl_info = check_ssl_certificate(url)
    metrics["ssl_valid"]          = 1 if ssl_info["valid"] else 0
    metrics["ssl_days_remaining"] = ssl_info["days_remaining"]
    metrics["ssl_expiry_date"]    = ssl_info["expiry_date"]
    metrics["ssl_issuer"]         = ssl_info["issuer"]
    metrics["ssl_tls_version"]    = ssl_info["tls_version"]
    metrics["ssl_expiring_soon"]  = ssl_info["expiring_soon"]
    metrics["ssl_error"]          = ssl_info["error"]

    if ssl_info["valid"]:
        print(f"  SSL: valid | {ssl_info['days_remaining']} days remaining | "
              f"Expires: {ssl_info['expiry_date'][:10]} | "
              f"Issuer: {ssl_info['issuer']} | TLS: {ssl_info['tls_version']}")
    else:
        print(f"  SSL: INVALID — {ssl_info['error']}")

    start_time = time.time()

    try:
        session = requests.Session()
        resp    = requests.get(url, timeout=TIMEOUT, verify=True)

        ttfb_ms = round((time.time() - start_time) * 1000, 2)

        metrics["status_code"]         = resp.status_code
        metrics["response_time_ms"]    = round((time.time() - start_time) * 1000, 2)
        metrics["ttfb_ms"]             = ttfb_ms
        metrics["response_size_bytes"] = len(resp.content)
        metrics["is_up"]               = 1 if resp.status_code == 200 else 0

        # Latency classification
        rt = metrics["response_time_ms"]
        if rt >= LATENCY_CRITICAL_MS:
            metrics["latency_status"] = "critical"
        elif rt >= LATENCY_WARNING_MS:
            metrics["latency_status"] = "warning"
        else:
            metrics["latency_status"] = "ok"

        # Security header audit
        header_findings = []
        for header, meta in SECURITY_HEADERS.items():
            if header not in resp.headers:
                header_findings.append({
                    "header":     header,
                    "severity":   meta["severity"],
                    "frameworks": meta["frameworks"],
                    "status":     "MISSING"
                })
        metrics["missing_headers"] = len(header_findings)
        metrics["header_findings"] = header_findings

        # Content integrity
        if resp.status_code == 200 and check_content:
            soup         = BeautifulSoup(resp.text, "html.parser")
            page_text    = soup.get_text()
            current_hash = hashlib.sha256(page_text.encode("utf-8")).hexdigest()
            metrics["content_hash"] = current_hash

            missing_elems = [e for e in expected_elems if e not in resp.text]
            metrics["missing_elements"] = missing_elems

            last_state = load_last_state(name)
            if last_state is None:
                save_current_hash(name, current_hash, commit_info)
                print(f"  Baseline saved for {name} — hash: {current_hash[:12]}... commit: {commit_info.get('sha','none')}")
            elif current_hash != last_state["hash"]:
                metrics["hash_changed"] = 1
                current_sha = commit_info.get("sha")
                saved_sha   = last_state.get("commit_sha")
                if current_sha and current_sha != saved_sha:
                    save_current_hash(name, current_hash, commit_info)
                    print(f"  Authorized change for {name} — new commit: {current_sha}")
                else:
                    metrics["unauthorized_change"] = 1
                    print(f"  UNAUTHORIZED change for {name} — hash changed but commit SHA unchanged ({saved_sha})")

    except requests.exceptions.SSLError as e:
        metrics["error"]    = f"SSL Error: {str(e)[:120]}"
        metrics["ssl_valid"] = 0
        metrics["response_time_ms"] = round((time.time() - start_time) * 1000, 2)

    except requests.exceptions.Timeout:
        metrics["error"]            = "Timeout"
        metrics["response_time_ms"] = TIMEOUT * 1000

    except requests.exceptions.RequestException as e:
        metrics["error"]            = f"Request Error: {str(e)[:120]}"
        metrics["response_time_ms"] = round((time.time() - start_time) * 1000, 2)

    except Exception as e:
        metrics["error"]            = f"Error: {str(e)[:120]}"
        metrics["response_time_ms"] = round((time.time() - start_time) * 1000, 2)

    return metrics


# ---------------------------------------------------------------------------
# InfluxDB writer
# ---------------------------------------------------------------------------
def send_to_influxdb(metrics_list: list) -> dict:
    lines = []
    for m in metrics_list:
        tags   = f"url={m['url']},name={m['name']},type={m['type']}"
        fields = [
            f"status_code={m['status_code']}i",
            f"response_time_ms={m['response_time_ms']}",
            f"ttfb_ms={m['ttfb_ms']}",
            f"response_size_bytes={m['response_size_bytes']}i",
            f"is_up={m['is_up']}i",
            f"ssl_valid={m['ssl_valid']}i",
            f"ssl_days_remaining={m['ssl_days_remaining']}i",
            f"missing_headers={m['missing_headers']}i",
            f"hash_changed={m['hash_changed']}i",
            f"unauthorized_change={m['unauthorized_change']}i",
        ]
        if m["content_hash"]:
            fields.append(f'content_hash="{m["content_hash"]}"')
        if m["ssl_tls_version"]:
            fields.append(f'ssl_tls_version="{m["ssl_tls_version"]}"')
        if m["ssl_issuer"]:
            fields.append(f'ssl_issuer="{m["ssl_issuer"]}"')
        if m["error"]:
            fields.append(f'error="{m["error"].replace(chr(34), chr(92)+chr(34))}"')

        ts = int(time.time() * 1e9)
        lines.append(f"website_monitoring,{tags} {','.join(fields)} {ts}")

    url     = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=ns"
    headers = {"Authorization": f"Token {INFLUXDB_TOKEN}", "Content-Type": "text/plain; charset=utf-8"}

    try:
        resp = requests.post(url, data="\n".join(lines), headers=headers)
        if resp.status_code == 204:
            return {"success": True, "points_written": len(metrics_list)}
        return {"success": False, "error": f"Status {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Alert builder and sender
# ---------------------------------------------------------------------------
def build_alert_email(alerts: list, commit_info: dict) -> tuple:
    critical_alerts = [a for a in alerts if a["severity"] == "CRITICAL"]
    subject = f"[GRC Monitor] {'🔴 CRITICAL' if critical_alerts else '⚠️ WARNING'} — {len(alerts)} alert(s) detected"

    rows = ""
    for a in alerts:
        icon = "🔴" if a["severity"] == "CRITICAL" else "⚠️"
        rows += f"""
        <tr>
            <td style='padding:8px;border:1px solid #ddd;'>{icon} {a['severity']}</td>
            <td style='padding:8px;border:1px solid #ddd;'>{a['site']}</td>
            <td style='padding:8px;border:1px solid #ddd;'>{a['type']}</td>
            <td style='padding:8px;border:1px solid #ddd;'>{a['detail']}</td>
        </tr>"""

    commit_section = ""
    if commit_info:
        commit_section = f"""
        <p><strong>Latest GitHub commit:</strong> {commit_info.get('sha','N/A')} —
        {commit_info.get('message','N/A')} ({commit_info.get('timestamp','N/A')})</p>"""

    body = f"""
    <html><body style='font-family:Arial,sans-serif;color:#333;'>
    <h2 style='color:#c0392b;'>GRC Synthetic Monitor — Alert Report</h2>
    <p><strong>Timestamp:</strong> {datetime.now(timezone.utc).isoformat()}</p>
    {commit_section}
    <table style='border-collapse:collapse;width:100%;margin-top:16px;'>
        <tr style='background:#f2f2f2;'>
            <th style='padding:8px;border:1px solid #ddd;text-align:left;'>Severity</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left;'>Site</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left;'>Alert Type</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left;'>Detail</th>
        </tr>
        {rows}
    </table>
    <p style='margin-top:24px;font-size:12px;color:#888;'>
        GRC Portfolio Synthetic Monitor — AWS Lambda + InfluxDB + Grafana
    </p>
    </body></html>"""

    return subject, body


def send_alert_email(subject: str, body: str):
    try:
        ses_client.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [ALERT_RECIPIENT]},
            Message={
                "Subject": {"Data": subject},
                "Body":    {"Html": {"Data": body}}
            }
        )
        print(f"  Alert email sent: {subject}")
    except Exception as e:
        print(f"  SES error: {e}")


# ---------------------------------------------------------------------------
# Alert evaluator with deduplication
# ---------------------------------------------------------------------------
def evaluate_alerts(metrics: dict, prev_state: dict) -> tuple:
    alerts    = []
    new_state = dict(prev_state)
    name      = metrics["name"]

    def flag(key, condition, severity, alert_type, detail):
        was_alerting = prev_state.get(key, False)
        if condition and not was_alerting:
            alerts.append({"severity": severity, "site": name, "type": alert_type, "detail": detail})
        new_state[key] = bool(condition)

    flag("is_down",       metrics["is_up"] == 0,
         "CRITICAL", "Site Down",
         f"Status {metrics['status_code']} — {metrics.get('error','')}")

    flag("ssl_invalid",   metrics["ssl_valid"] == 0,
         "CRITICAL", "SSL Invalid",
         metrics.get("ssl_error") or "SSL certificate validation failed")

    flag("ssl_expiring",  metrics["ssl_expiring_soon"],
         "WARNING",  "SSL Certificate Expiring Soon",
         f"Certificate expires in {metrics['ssl_days_remaining']} days ({metrics.get('ssl_expiry_date','')[:10]})")

    flag("latency_crit",  metrics["latency_status"] == "critical",
         "CRITICAL", "High Latency",
         f"{metrics['response_time_ms']}ms exceeds {LATENCY_CRITICAL_MS}ms threshold")

    flag("latency_warn",  metrics["latency_status"] == "warning",
         "WARNING",  "Elevated Latency",
         f"{metrics['response_time_ms']}ms exceeds {LATENCY_WARNING_MS}ms threshold")

    flag("unauth_change", metrics["unauthorized_change"] == 1,
         "CRITICAL", "Unauthorized Content Change",
         "Hash changed with no recent GitHub commit — possible unauthorized S3 modification")

    flag("missing_elems", len(metrics["missing_elements"]) > 0,
         "WARNING",  "Missing Portfolio Elements",
         f"Elements not found: {', '.join(metrics['missing_elements'])}")

    crit_headers = [f["header"] for f in metrics["header_findings"] if f["severity"] == "CRITICAL"]
    flag("crit_headers",  len(crit_headers) > 0,
         "WARNING",  "Critical Security Headers Missing",
         f"{', '.join(crit_headers)}")

    return alerts, new_state


# ---------------------------------------------------------------------------
# S3 audit report
# ---------------------------------------------------------------------------
def save_audit_report(all_metrics: list, commit_info: dict, influxdb_result: dict):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key       = f"synthetic-monitor/reports/{timestamp}.json"
    report    = {
        "report_title":         "Synthetic Monitoring Run",
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "framework_references": ["SOC 2 A1.1", "SOC 2 A1.2", "SOC 2 CC8.1",
                                 "NIST SP 800-53 AU-12", "ISO 27001 A.12.1"],
        "github_commit":        commit_info,
        "influxdb_result":      influxdb_result,
        "sites":                all_metrics
    }
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET, Key=key,
            Body=json.dumps(report, indent=2),
            ContentType="application/json"
        )
        print(f"  Audit report saved: {key}")
    except Exception as e:
        print(f"  Error saving audit report: {e}")


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    print(f"Synthetic monitor starting at {datetime.now(timezone.utc).isoformat()}")

    commit_info = get_latest_github_commit(GITHUB_REPO)
    if commit_info:
        print(f"Latest commit: {commit_info['sha']} — {commit_info['message']}")

    all_metrics    = []
    all_new_alerts = []

    for site in WEBSITES:
        print(f"\nChecking {site['name']} — {site['url']}")
        metrics = check_website(site, commit_info)
        all_metrics.append(metrics)

        if metrics["is_up"]:
            print(f"  ✓ UP — {metrics['response_time_ms']}ms | TTFB: {metrics['ttfb_ms']}ms | "
                  f"Size: {metrics['response_size_bytes']} bytes | "
                  f"Missing headers: {metrics['missing_headers']}")
        else:
            print(f"  ✗ DOWN — Status: {metrics['status_code']} | Error: {metrics['error']}")

        prev_state              = load_alert_state(site["name"])
        new_alerts, new_state   = evaluate_alerts(metrics, prev_state)
        save_alert_state(site["name"], new_state)

        if new_alerts:
            all_new_alerts.extend(new_alerts)
            print(f"  ⚠️  {len(new_alerts)} new alert(s) for {site['name']}")

    if all_new_alerts:
        subject, body = build_alert_email(all_new_alerts, commit_info)
        send_alert_email(subject, body)

    print("\nSending metrics to InfluxDB...")
    influxdb_result = send_to_influxdb(all_metrics)
    if influxdb_result["success"]:
        print(f"  ✓ {influxdb_result['points_written']} points written")
    else:
        print(f"  ✗ InfluxDB error: {influxdb_result['error']}")

    save_audit_report(all_metrics, commit_info, influxdb_result)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message":          "Monitoring check completed",
            "websites_checked": len(all_metrics),
            "new_alerts":       len(all_new_alerts),
            "influxdb_result":  influxdb_result
        })
    }

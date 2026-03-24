import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    ses = boto3.client('ses')

    BUCKET_LIFECYCLE = 'grc-access-lifecycle-states'
    BUCKET_AUDIT = 'grc-audit-reports-465352048537'

    username = event.get('username')
    action = event.get('action')
    reason = event.get('reason', 'No reason provided')
    requested_by = event.get('requested_by', 'system')
    send_email = event.get('send_email', False)
    email_to = event.get('email_to', None)
    sender_email = event.get('sender_email', None)

    if not username or not action:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing required parameters: username and action'
            })
        }

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    file_timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    if action == 'terminate':
        result = terminate_user(iam, username, reason, requested_by, timestamp)
    elif action == 'suspend':
        result = suspend_user(iam, s3, BUCKET_LIFECYCLE, username, reason, requested_by, timestamp)
    elif action == 'reactivate':
        result = reactivate_user(iam, s3, BUCKET_LIFECYCLE, username, reason, requested_by, timestamp)
    else:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': f'Invalid action: {action}. Valid actions: terminate, suspend, reactivate'
            })
        }

    # Extraer el body del resultado para guardarlo en S3
    result_body = json.loads(result['body'])

    # Guardar audit log en bucket central
    s3_key = f"access-lifecycle-manager/{file_timestamp}_{action}_{username}.json"
    s3.put_object(
        Bucket=BUCKET_AUDIT,
        Key=s3_key,
        Body=json.dumps(result_body, indent=2),
        ContentType='application/json'
    )
    result_body["audit_log_saved"] = f"s3://{BUCKET_AUDIT}/{s3_key}"

    # Enviar email si se solicita
    if send_email and email_to and sender_email:
        actions_taken_text = "\n".join(
            f"  - {a}" for a in result_body.get("actions_taken", [])
        )

        email_body = (
            f"Access Lifecycle Manager — Action Confirmation\n"
            f"Generated: {timestamp}\n\n"
            f"ACTION SUMMARY\n"
            f"--------------\n"
            f"Action       : {action.upper()}\n"
            f"Username     : {username}\n"
            f"Requested By : {requested_by}\n"
            f"Reason       : {reason}\n"
            f"Status       : {result_body.get('status', 'COMPLETED')}\n\n"
            f"STEPS EXECUTED\n"
            f"--------------\n"
            f"{actions_taken_text}\n\n"
            f"AUDIT LOG\n"
            f"---------\n"
            f"s3://{BUCKET_AUDIT}/{s3_key}\n\n"
            f"---\n"
            f"GRC Automation Toolkit | Access Lifecycle Manager\n"
            f"Control References: ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2\n"
        )

        ses.send_email(
            Source=sender_email,
            Destination={'ToAddresses': [email_to]},
            Message={
                'Subject': {
                    'Data': f"Access Lifecycle: {action.upper()} — {username} — {file_timestamp}",
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
        result_body["email_sent_to"] = email_to

    print(json.dumps(result_body, indent=2))
    return {'statusCode': 200, 'body': json.dumps(result_body, indent=2)}


def terminate_user(iam, username, reason, requested_by, timestamp):
    actions_taken = []

    try:
        iam.delete_login_profile(UserName=username)
        actions_taken.append("Console access removed")
    except iam.exceptions.NoSuchEntityException:
        actions_taken.append("Console access was not enabled")

    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        iam.update_access_key(
            UserName=username,
            AccessKeyId=key['AccessKeyId'],
            Status='Inactive'
        )
        actions_taken.append(f"Access key {key['AccessKeyId']} deactivated")

    attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for policy in attached:
        iam.detach_user_policy(
            UserName=username,
            PolicyArn=policy['PolicyArn']
        )
        actions_taken.append(f"Policy {policy['PolicyName']} detached")

    result = {
        "action": "TERMINATE",
        "username": username,
        "timestamp": timestamp,
        "requested_by": requested_by,
        "reason": reason,
        "actions_taken": actions_taken,
        "control_reference": "ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2",
        "status": "COMPLETED"
    }

    print(json.dumps(result, indent=2))
    return {'statusCode': 200, 'body': json.dumps(result, indent=2)}


def suspend_user(iam, s3, bucket, username, reason, requested_by, timestamp):
    actions_taken = []
    previous_state = {
        "username": username,
        "suspended_at": timestamp,
        "reason": reason,
        "requested_by": requested_by,
        "had_console_access": False,
        "access_keys": [],
        "attached_policies": []
    }

    try:
        iam.get_login_profile(UserName=username)
        previous_state["had_console_access"] = True
        iam.update_login_profile(UserName=username, PasswordResetRequired=True)
        actions_taken.append("Console access suspended")
    except iam.exceptions.NoSuchEntityException:
        actions_taken.append("Console access was not enabled")

    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        previous_state["access_keys"].append({
            "key_id": key['AccessKeyId'],
            "previous_status": key['Status']
        })
        if key['Status'] == 'Active':
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            actions_taken.append(f"Access key {key['AccessKeyId']} deactivated")

    attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for policy in attached:
        previous_state["attached_policies"].append({
            "policy_name": policy['PolicyName'],
            "policy_arn": policy['PolicyArn']
        })

    s3.put_object(
        Bucket=bucket,
        Key=f"suspended/{username}.json",
        Body=json.dumps(previous_state, indent=2),
        ContentType='application/json'
    )
    actions_taken.append(f"Previous state saved to S3: suspended/{username}.json")

    result = {
        "action": "SUSPEND",
        "username": username,
        "timestamp": timestamp,
        "requested_by": requested_by,
        "reason": reason,
        "actions_taken": actions_taken,
        "state_saved": f"s3://{bucket}/suspended/{username}.json",
        "control_reference": "ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2",
        "status": "COMPLETED"
    }

    print(json.dumps(result, indent=2))
    return {'statusCode': 200, 'body': json.dumps(result, indent=2)}


def reactivate_user(iam, s3, bucket, username, reason, requested_by, timestamp):
    actions_taken = []

    try:
        response = s3.get_object(Bucket=bucket, Key=f"suspended/{username}.json")
        previous_state = json.loads(response['Body'].read().decode('utf-8'))
    except s3.exceptions.NoSuchKey:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'error': f'No suspended state found for user {username}. Was this user suspended through this system?'
            })
        }

    if previous_state.get("had_console_access"):
        try:
            iam.create_login_profile(
                UserName=username,
                Password='TempPassword123!',
                PasswordResetRequired=True
            )
            actions_taken.append("Console access restored — password reset required on next login")
        except iam.exceptions.EntityAlreadyExistsException:
            actions_taken.append("Console access already exists")

    for key in previous_state.get("access_keys", []):
        if key["previous_status"] == "Active":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["key_id"],
                Status='Active'
            )
            actions_taken.append(f"Access key {key['key_id']} reactivated")

    for policy in previous_state.get("attached_policies", []):
        try:
            iam.attach_user_policy(
                UserName=username,
                PolicyArn=policy["policy_arn"]
            )
            actions_taken.append(f"Policy {policy['policy_name']} restored")
        except Exception as e:
            actions_taken.append(f"Could not restore policy {policy['policy_name']}: {str(e)}")

    s3.delete_object(Bucket=bucket, Key=f"suspended/{username}.json")
    actions_taken.append("Suspension record removed from S3")

    result = {
        "action": "REACTIVATE",
        "username": username,
        "timestamp": timestamp,
        "requested_by": requested_by,
        "reason": reason,
        "suspended_since": previous_state.get("suspended_at"),
        "original_suspension_reason": previous_state.get("reason"),
        "actions_taken": actions_taken,
        "control_reference": "ISO 27001 A.5.18 / NIST AC-2 / SOC 2 CC6.2",
        "status": "COMPLETED"
    }

    print(json.dumps(result, indent=2))
    return {'statusCode': 200, 'body': json.dumps(result, indent=2)}

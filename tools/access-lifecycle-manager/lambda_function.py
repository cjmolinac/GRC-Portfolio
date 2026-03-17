import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    
    BUCKET = 'grc-access-lifecycle-states'
    
    username = event.get('username')
    action = event.get('action')
    reason = event.get('reason', 'No reason provided')
    requested_by = event.get('requested_by', 'system')
    
    if not username or not action:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing required parameters: username and action'
            })
        }
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    if action == 'terminate':
        return terminate_user(iam, username, reason, requested_by, timestamp)
    elif action == 'suspend':
        return suspend_user(iam, s3, BUCKET, username, reason, requested_by, timestamp)
    elif action == 'reactivate':
        return reactivate_user(iam, s3, BUCKET, username, reason, requested_by, timestamp)
    else:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': f'Invalid action: {action}. Valid actions: terminate, suspend, reactivate'
            })
        }


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

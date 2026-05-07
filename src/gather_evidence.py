import json
import time
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
# TODO: Integrate save_json into evidence_client
from utils import save_json

def save_audit_evidence(evidence_client, in_scope_regions):
    save_s3_evidence(evidence_client)
    save_iam_evidence(evidence_client)
    save_guardduty_evidence(evidence_client, in_scope_regions)

# NOTE: Consider making these calls concurrently to speed up the evidence collection
def save_s3_evidence(evidence_client):
    print("Saving S3 evidence.")

    # NOTE: s3_client is used to avoid creating multiple AWS clients.
    s3_client = evidence_client.session.client("s3")

    # Obtain a list of buckets.
    buckets = evidence_client.get_aws(
        "s3/buckets.json",
        client=s3_client,
        method="list_buckets"
    )

    # Save evidence related to each S3 bucket.
    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket['Name']
        # Save encryption settings.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/encryption.json",
            client=s3_client,
            method="get_bucket_encryption",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["ServerSideEncryptionConfigurationNotFoundError"]
        )
        # Save public access block.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/public_access_block.json",
            client=s3_client,
            method="get_public_access_block",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )
        # Save tags.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/tags.json",
            client=s3_client,
            method="get_bucket_tagging",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchTagSet"]
        )
        # Save bucket policy
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/bucket_policy.json",
            client=s3_client,
            method="get_bucket_policy",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchBucketPolicy"]
        )  

def save_iam_evidence(evidence_client):
    print('Gathering IAM evidence')

    iam_client = evidence_client.session.client("iam")
    cloudtrail_client = evidence_client.session.client("cloudtrail")

    # Save a list of iam users created in the last 90 days.
    # NOTE: CloudTrail currently allows lookbacks of 90 days without setting up additional tools (e.g Athena).
    start_time = datetime.now(timezone.utc) - timedelta(days=90)
    evidence_client.get_aws(
        "iam/new_iam_users.json",
        client=cloudtrail_client,
        paginator_params={
            "method_name": "lookup_events",
            "pagination_key": "Events",
            "params": {
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "CreateUser",
                    }
                ],
                "StartTime": start_time,
            },
        }
    )

    # Save IAM credentials report (json and csv version). NOTE: This will time out after 30 seconds
    iam_client.generate_credential_report()
    for _ in range(30):
        try:
            credentialReport = iam_client.get_credential_report()
            break  # success = report is ready
        except ClientError as e:
            if e.response["Error"]["Code"] == "CredentialReportNotReady":
                time.sleep(2)
                continue
            raise
    else:
        raise TimeoutError("IAM credential report timed out after 30 seconds.")
    save_json(credentialReport, f"{evidence_client.base_path}/iam/credentials_report.json")
    # Convert credentials report to a CSV
    decodedCredentialReport = credentialReport['Content'].decode("utf-8")
    with open(f"{evidence_client.base_path}/iam/credentials_report.csv", "w") as file:
        file.write(decodedCredentialReport)
    
    # Collect IAM administrative access evidence
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    users = evidence_client.get_aws(
        "iam/admin/policy_users.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_entities_for_policy",
            "pagination_key": "PolicyUsers",
            "params": {"PolicyArn": policy_arn},
        }
    )
    groups = evidence_client.get_aws(
        "iam/admin/policy_groups.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_entities_for_policy",
            "pagination_key": "PolicyGroups",
            "params": {"PolicyArn": policy_arn},
        }
    )
    roles = evidence_client.get_aws(
        "iam/admin/policy_roles.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_entities_for_policy",
            "pagination_key": "PolicyRoles",
            "params": {"PolicyArn": policy_arn},
        }
    )

    # Combine into one file and save
    combined_administrative_entities = {
        "PolicyUsers": users.get("PolicyUsers", []),
        "PolicyGroups": groups.get("PolicyGroups", []),
        "PolicyRoles": roles.get("PolicyRoles", []),
        # Keep metadata from the last call
        "ResponseMetadata": roles.get("ResponseMetadata"),
    }
    save_json(combined_administrative_entities, f"{evidence_client.base_path}/iam/administrative_entities.json")
    
    # Obtain a list of iam groups.
    groups = evidence_client.get_aws(
        "iam/groups.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_groups",
            "pagination_key": "Groups",
        }
    )
    # Save evidence for each iam group.
    for group in groups.get("Groups"):
        group_name = group["GroupName"]
        # Group members
        evidence_client.get_aws(
            f"iam/groups/{group_name}/group_members.json",
            client=iam_client,
            paginator_params={
                "method_name": "get_group",
                "pagination_key": "Users",
                "params": {"GroupName": group_name},
            }
        )
        # Attached managed policies
        evidence_client.get_aws(
            f"iam/groups/{group_name}/attached_managed_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_attached_group_policies",
                "pagination_key": "AttachedPolicies",
                "params": {"GroupName": group_name},
            }
        )
        # Inline policy names
        inline_policies = evidence_client.get_aws(
            f"iam/groups/{group_name}/inline_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_group_policies",
                "pagination_key": "PolicyNames",
                "params": {"GroupName": group_name},
            }
        )
        # Inline policy documents
        for policy_name in inline_policies.get("PolicyNames", []):
            evidence_client.get_aws(
                f"iam/groups/{group_name}/inline_policies/{policy_name}.json",
                client=iam_client,
                method="get_group_policy",
                method_kwargs={
                    "GroupName": group_name,
                    "PolicyName": policy_name,
                }
            )

    # Obtain a list of iam users.
    users = evidence_client.get_aws(
        "iam/users.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_users",
            "pagination_key": "Users",
        }
    )
    # Save evidence for each iam user.
    for user in users.get("Users"):
        username = user["UserName"]
        # Managed policies attached to user
        evidence_client.get_aws(
            f"iam/users/{username}/attached_managed_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_attached_user_policies",
                "pagination_key": "AttachedPolicies",
                "params": {"UserName": username},
            }
        )
        # Inline policy names
        inline_policies = evidence_client.get_aws(
            f"iam/users/{username}/inline_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_user_policies",
                "pagination_key": "PolicyNames",
                "params": {"UserName": username},
            }
        ) 
        # Inline policy documents
        for policy_name in inline_policies.get("PolicyNames", []):
            evidence_client.get_aws(
                f"iam/users/{username}/inline_policies/{policy_name}.json",
                client=iam_client,
                method="get_user_policy",
                method_kwargs={
                    "UserName": username,
                    "PolicyName": policy_name,
                }
            )
        # Group membership
        evidence_client.get_aws(
            f"iam/users/{username}/group_membership.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_groups_for_user",
                "pagination_key": "Groups",
                "params": {"UserName": username},
            }
        )

    # Obtain a list of iam roles.
    roles = evidence_client.get_aws(
        "iam/roles.json",
        client=iam_client,
        paginator_params={
            "method_name": "list_roles",
            "pagination_key": "Roles",
        }
    )

    # Save evidence for each iam role
    for role in roles.get("Roles", []):
        # NOTE: RoleName can contain '/', so this replacement is required to normalize how evidence is saved.
        role_name = role["RoleName"].replace('/', '_')

        # Full role metadata (includes assume role policy, arn, etc.)
        evidence_client.get_aws(
            f"iam/roles/{role_name}/role_details.json",
            client=iam_client,
            method="get_role",
            method_kwargs={"RoleName": role_name},
        )

        # Attached managed policies
        evidence_client.get_aws(
            f"iam/roles/{role_name}/attached_managed_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_attached_role_policies",
                "pagination_key": "AttachedPolicies",
                "params": {"RoleName": role_name},
            }
        )
        # Inline policy names
        inline_policies = evidence_client.get_aws(
            f"iam/roles/{role_name}/inline_policies.json",
            client=iam_client,
            paginator_params={
                "method_name": "list_role_policies",
                "pagination_key": "PolicyNames",
                "params": {"RoleName": role_name},
            }
        )
        # Inline policy documents
        for policy_name in inline_policies.get("PolicyNames", []):
            evidence_client.get_aws(
                f"iam/roles/{role_name}/inline_policies/{policy_name}.json",
                client=iam_client,
                method="get_role_policy",
                method_kwargs={
                    "RoleName": role_name,
                    "PolicyName": policy_name,
                }
            )
        # Trust policy (important for security audits)
        trust_doc = role.get("AssumeRolePolicyDocument")
        if trust_doc:
            save_json(
                trust_doc,
                f"{evidence_client.base_path}/iam/roles/{role_name}/trust_policy.json"
            )

def save_guardduty_evidence(evidence_client, in_scope_regions):
    print('Gathering GuardDuty evidence')
    for region in in_scope_regions:
        guardduty_client = evidence_client.session.client('guardduty', region_name=region)

        detectors = evidence_client.get_aws(
            f"guardduty/{region}/detectors.json",
            client = guardduty_client,
            paginator_params={
                "method_name": "list_detectors",
                "pagination_key": "DetectorIds",
            }            
        )

        for detector_id in detectors['DetectorIds']:
            evidence_client.get_aws(
                f"guardduty/{region}/{detector_id}/config.json",
                service="guardduty",
                region=region,
                method="get_detector",
                method_kwargs={"DetectorId": detector_id}
            )
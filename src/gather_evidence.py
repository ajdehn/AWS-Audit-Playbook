import json
import time
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from utils import save_json

def save_audit_evidence(evidence_client, in_scope_regions):
    # NOTE: Save evidence that isn't associated with automated tests (e.g. EventBridge, IAM Groups, etc.)
    # NOTE: This is slightly more efficient because it doesn't create a new client each time it calls get_aws(). 
    save_s3_evidence(evidence_client)
    save_iam_evidence(evidence_client)
    save_guardduty_evidence(evidence_client, in_scope_regions)
    save_eventbridge_evidence(evidence_client, in_scope_regions)
    save_ec2_evidence(evidence_client, in_scope_regions)

# NOTE: Consider making these calls concurrently to speed up the evidence collection
def save_s3_evidence(evidence_client):
    print("Saving S3 evidence.")

    # NOTE: s3_client is used to avoid creating multiple AWS clients.
    s3_client = evidence_client.session.client("s3")

    # Obtain a list of buckets.
    buckets = evidence_client.get_aws("s3/buckets.json", client=s3_client, method="list_buckets")

    # Save evidence related to each S3 bucket.
    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket['Name']
        # Save each bucket's encryption settings.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/encryption.json", client=s3_client,
            method="get_bucket_encryption", method_kwargs={"Bucket": bucket_name},
            not_found_codes=["ServerSideEncryptionConfigurationNotFoundError"]
        )
        # Save bucket's public access block settings.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/public_access_block.json", client=s3_client,
            method="get_public_access_block", method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )
        # Save bucket's tags.
        evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/tags.json", client=s3_client,
            method="get_bucket_tagging", method_kwargs={"Bucket": bucket_name},
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

def save_ec2_evidence(evidence_client, in_scope_regions):
    print("Gathering EC2 evidence")

    for region in in_scope_regions:
        elbv2_client = evidence_client.session.client("elbv2", region_name=region)
        autoscaling_client = evidence_client.session.client("autoscaling", region_name=region)

        load_balancers = evidence_client.get_aws(
            f"elbv2/{region}/load_balancers.json",
            client=elbv2_client,
            paginator_params={
                "method_name": "describe_load_balancers",
                "pagination_key": "LoadBalancers",
            }
        )

        for lb in load_balancers.get("LoadBalancers", []):
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]

            # Save load balancer attributes.
            evidence_client.get_aws(
                f"elbv2/{region}/load_balancers/{lb_name}/attributes.json",
                client=elbv2_client,
                method="describe_load_balancer_attributes",
                method_kwargs={
                    "LoadBalancerArn": lb_arn
                }
            )

            # Save listeners.
            evidence_client.get_aws(
                f"elbv2/{region}/load_balancers/{lb_name}/listeners.json",
                client=elbv2_client,
                method="describe_listeners",
                method_kwargs={
                    "LoadBalancerArn": lb_arn
                }
            )

            # Save tags.
            evidence_client.get_aws(
                f"elbv2/{region}/load_balancers/{lb_name}/tags.json",
                client=elbv2_client,
                method="describe_tags",
                method_kwargs={
                    "ResourceArns": [lb_arn]
                }
            )

        auto_scaling_groups = evidence_client.get_aws(
            f"autoscaling/{region}/groups.json",
            client=autoscaling_client,
            paginator_params={
                "method_name": "describe_auto_scaling_groups",
                "pagination_key": "AutoScalingGroups",
            }
        )

        for asg in auto_scaling_groups.get("AutoScalingGroups", []):
            asg_name = asg["AutoScalingGroupName"]

            # Save ASG configuration/details.
            evidence_client.get_aws(
                f"autoscaling/{region}/groups/{asg_name}/details.json",
                client=autoscaling_client,
                method="describe_auto_scaling_groups",
                method_kwargs={
                    "AutoScalingGroupNames": [asg_name]
                }
            )

            # Save scaling policies.
            evidence_client.get_aws(
                f"autoscaling/{region}/groups/{asg_name}/policies.json",
                client=autoscaling_client,
                method="describe_policies",
                method_kwargs={
                    "AutoScalingGroupName": asg_name
                }
            )

            # Save tags.
            evidence_client.get_aws(
                f"autoscaling/{region}/groups/{asg_name}/tags.json",
                client=autoscaling_client,
                method="describe_tags",
                method_kwargs={
                    "Filters": [
                        {
                            "Name": "auto-scaling-group",
                            "Values": [asg_name]
                        }
                    ]
                }
            )

def save_eventbridge_evidence(evidence_client, in_scope_regions):
    print("Gathering EventBridge evidence")

    for region in in_scope_regions:
        events_client = evidence_client.session.client("events", region_name=region)

        # Obtain all event buses in the region.
        event_buses = evidence_client.get_aws(
            f"eventbridge/{region}/event_buses.json",
            client=events_client,
            method="list_event_buses"
        )

        # Save evidence related to each event bus.
        for event_bus in event_buses.get("EventBuses", []):
            bus_name = event_bus["Name"]

            # Save event bus details.
            evidence_client.get_aws(
                f"eventbridge/{region}/{bus_name}/details.json",
                service="events",
                region=region,
                method="describe_event_bus",
                method_kwargs={"Name": bus_name}
            )

            # Obtain rules for the event bus.
            rules = evidence_client.get_aws(
                f"eventbridge/{region}/{bus_name}/rules.json",
                service="events",
                region=region,
                method="list_rules",
                method_kwargs={"EventBusName": bus_name}
            )

            # Save evidence related to each rule.
            for rule in rules.get("Rules", []):
                rule_name = rule["Name"]

                # Save rule details.
                evidence_client.get_aws(
                    f"eventbridge/{region}/{bus_name}/rules/{rule_name}/details.json",
                    service="events",
                    region=region,
                    method="describe_rule",
                    method_kwargs={
                        "Name": rule_name,
                        "EventBusName": bus_name
                    }
                )

                # Save targets.
                evidence_client.get_aws(
                    f"eventbridge/{region}/{bus_name}/rules/{rule_name}/targets.json",
                    service="events",
                    region=region,
                    method="list_targets_by_rule",
                    method_kwargs={
                        "Rule": rule_name,
                        "EventBusName": bus_name
                    }
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
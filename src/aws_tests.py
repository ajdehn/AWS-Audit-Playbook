from utils import is_test_excluded, evaluate_tags
from sample import Sample
from test import Test
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta
import traceback

def run_test_safely(audit, test_fn, test_id):
    try:
        return test_fn(audit, test_id)
    except Exception as e:

        print(f"\nERROR running test: {test_id}")
        print(f"Exception: {e}\n")
        traceback.print_exc()

        # Create a failed test object
        test = Test(
            test_id=test_id,
            test_description=f"{test_id} (Execution Failed)",
            test_procedures=["Test execution failed."],
            test_attributes=[],
            table_headers=["Error"],
            risk_rating=3
        )
        test.is_passing = False
        test.comments = f"Test execution failed. Please manually investigate."
        print(f"ERROR: Running {test_id} test failed. Moving to the next test.")

        return test

def run_all_tests(audit):
    # TODO: Add IAM tests (IAM User Stale Access Keys)
    # TODO: Add S3 object owner check
    # TODO: Add EC2 Public Ports (22, RDS, all ports, etc)
    # TODO: Add WAF Tags
    # TODO: Add GuardDuty findings resolved within a set time period.
    # TODO: Add GuardDuty findings sent to EventBridge every 15 minutes (default is 6 hours).

    test_definitions = [
        ("iam_root_mfa", test_iam_root_mfa),
        ("iam_root_access_key", test_iam_root_access_key),
        ("iam_users_mfa", test_iam_users_mfa),
        ("iam_user_access_key_age", test_iam_user_access_key_age),
        ("iam_password_policy", test_iam_password_policy),
        ("s3_encryption", test_s3_encryption),
        ("s3_public_access", test_s3_public_access),
        ("s3_secure_transport", test_s3_secure_transport),
        ("s3_tags", test_s3_tags),
        ("rds_backup_retention", test_rds_backup_retention),
        ("rds_encryption", test_rds_encryption),
        ("rds_public_access", test_rds_public_access),
        ("rds_auto_minor_version_upgrade", test_rds_auto_minor_version_upgrade),
        ("rds_deletion_protection", test_rds_deletion_protection),
        ("rds_tags", test_rds_tags),
        ("ebs_volume_encryption", test_ebs_volume_encryption),
        ("ebs_default_encryption", test_ebs_default_encryption),
        ("ebs_tags", test_ebs_tags),
        ("ec2_tags", test_ec2_tags),
        ("ec2_security_group_tags", test_ec2_security_group_tags),
        ("lambda_tags", test_lambda_tags),
        ("cloudtrail_multi_region", test_cloudtrail_multi_region),
        ("cloudtrail_log_file_validation", test_cloudtrail_log_file_validation),
        ("cloudtrail_s3_bucket_protection", test_cloudtrail_s3_bucket_protection),
        ("cloudtrail_logging_recent_stops", test_cloudtrail_logging_recent_stops),
        ("wafv2_enabled", test_wafv2_enabled),
        ("guardduty_enabled", test_guardduty_enabled),
    ]

    tests = []
    for test_id, test_fn in test_definitions:
        if is_test_excluded(test_id, audit.config):
            # Move to next test.
            continue
        else:
            tests.append(run_test_safely(audit, test_fn, test_id))
    
    return tests

def test_s3_encryption(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="S3 buckets are encrypted at rest.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: s3/buckets.json.",
            "For each S3 bucket, obtained the encryption settings by calling the get_bucket_encryption() boto3 command.",
            "For each S3 bucket, saved the encryption settings: s3/buckets/[bucket_name]/encryption.json.",
            "For each S3 bucket, inspected the encryption settings to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["ServerSideEncryptionConfiguration is present in encryption.json."],
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )
    
    # Obtain and save list of buckets.
    buckets = audit.evidence_client.get_aws(
        "s3/buckets.json",
        service="s3",
        method="list_buckets"
    )

    # Loop through each bucket
    for bucket in buckets.get("Buckets", []):
        sample = Sample(sample_id={"bucket_name": bucket['Name']})
        if sample.check_excluded(test, audit):
            continue

        # Obtain and save bucket's encryption settings.
        enc = audit.evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/encryption.json",
            service="s3",
            method="get_bucket_encryption",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["ServerSideEncryptionConfigurationNotFoundError"]
        )
        if enc.get("ServerSideEncryptionConfiguration"):
            sample.is_passing = True
        else:
            sample.comments = "No encryption configuration found"
        test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} S3 bucket(s) are not encrypted."
    return test

def test_s3_public_access(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="S3 buckets are configured to block public access.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: s3/buckets.json.",
            "For each bucket, obtained the public access block settings by calling the get_public_access_block() boto3 command.",
            "For each bucket, saved the public access block settings: s3/buckets/[bucket_name]/public_access_block.json.",
            "For each bucket, inspected the public access block settings to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets are set to true."],
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    # Obtain and save list of buckets.
    buckets = audit.evidence_client.get_aws(
        "s3/buckets.json",
        service="s3",
        method="list_buckets"
    )

    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket["Name"]
        sample = Sample(sample_id={"bucket_name": bucket_name})
        if sample.check_excluded(test, audit):
            continue
        
        # Fetch public access block
        public_access_block = audit.evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/public_access_block.json",
            service="s3",
            method="get_public_access_block",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )        
        if not public_access_block:
            sample.comments = "No Public Access Block configuration found."
            test.samples.append(sample)
            continue

        config = public_access_block.get("PublicAccessBlockConfiguration", {})
        block_acls = config.get("BlockPublicAcls", False)
        ignore_acls = config.get("IgnorePublicAcls", False)
        block_policy = config.get("BlockPublicPolicy", False)
        restrict_buckets = config.get("RestrictPublicBuckets", False)

        # Document conclusion
        is_blocking_public_access = all([block_acls, ignore_acls, block_policy, restrict_buckets])
        if is_blocking_public_access:
            sample.is_passing = True
        else:
            sample.comments = "One or more public access settings are disabled."
        test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} S3 buckets are not blocking public access."
    return test

# TODO: Update logic for opt-in regions
def test_s3_tags(audit, test_id, risk_rating=1):
    # Get base required tags.
    test_config = audit.config.get("test_config") or {}
    base_required_tags = test_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Check if 's3_required_tags' is set. If so, override base required tags.
    test_config = audit.config.get("test_config") or {}
    s3_required_tags = test_config.get("s3_required_tags")
    if s3_required_tags:
        required_tags = s3_required_tags
    else:
        required_tags = base_required_tags

    test = Test(
        test_id=test_id,
        test_description=(
            "S3 buckets must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: s3/buckets.json.",
            "For each bucket, obtained its tags by calling the get_bucket_tagging() boto3 command.",
            "For each bucket, saved the tags: s3/buckets/[bucket_name]/tags.json.",
            f"For each bucket, inspected the tags to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    buckets = audit.evidence_client.get_aws(
        "s3/buckets.json",
        service="s3",
        method="list_buckets"
    )

    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket["Name"]
        sample = Sample(sample_id={"bucket_name": bucket_name})
        if sample.check_excluded(test, audit):
            continue

        # Fetch bucket tags
        tags_response = audit.evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/tags.json",
            service="s3",
            method="get_bucket_tagging",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchTagSet"]
        )

        if not tags_response:
            sample.comments = "Tags not found on this bucket."
            test.samples.append(sample)
            continue

        actual_bucket_tags = {t["Key"]: t.get("Value", "") for t in tags_response.get("TagSet", [])}
        evaluate_tags(sample, required_tags, actual_bucket_tags)
        test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} bucket(s) missing required tags or have empty values."
        )

    return test

def test_s3_secure_transport(audit, test_id, risk_rating=0):
    test = Test(
        test_id=test_id,
        test_description= "S3 buckets are configured to deny unencrypted data in-transit.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: s3/buckets.json.",
            "For each bucket, obtained the bucket policy by calling the get_bucket_policy() boto3 command.",
            "For each bucket, saved the bucket policy: s3/buckets/[bucket_name]/bucket_policy.json.",
            "For each bucket, inspected the bucket policy to determine if a statement exists that denies requests when aws:SecureTransport is false."
        ],
        test_attributes=[],
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    # Obtain and save list of buckets
    buckets = audit.evidence_client.get_aws(
        "s3/buckets.json",
        service="s3",
        method="list_buckets"
    )

    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket["Name"]
        sample = Sample(sample_id={"bucket_name": bucket_name})
        if sample.check_excluded(test, audit):
            continue

        # Fetch bucket policy
        policy = audit.evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/bucket_policy.json",
            service="s3",
            method="get_bucket_policy",
            method_kwargs={"Bucket": bucket_name},
            not_found_codes=["NoSuchBucketPolicy"]
        )

        if not policy:
            sample.comments = "No bucket policy found."
            test.samples.append(sample)
            continue

        try:
            policy_doc = json.loads(policy.get("Policy", "{}"))
        except Exception:
            sample.comments = "Unable to parse bucket policy."
            test.samples.append(sample)
            continue

        statements = policy_doc.get("Statement", [])

        # Normalize to list
        if isinstance(statements, dict):
            statements = [statements]

        secure_transport_enforced = False
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            condition = stmt.get("Condition", {})
            bool_condition = condition.get("Bool", {})
            if bool_condition.get("aws:SecureTransport") == "false":
                secure_transport_enforced = True
                break

        if secure_transport_enforced:
            sample.is_passing = True
        else:
            sample.comments = "No bucket policy statement enforcing SecureTransport."

        test.samples.append(sample)

    test.evaluate_samples()

    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} S3 bucket(s) do not enforce secure transport (HTTPS)."
        )

    return test

def test_iam_password_policy(audit, test_id, risk_rating=2):
    # Retrieve values from config. If not available, use defaults.
    test_config = audit.config.get("test_config") or {}
    required_min_length = test_config.get("iam_password_min_length", 14)
    req_min_complexity_types = test_config.get("iam_password_min_complexity_types", 4)
    required_password_history = test_config.get("iam_password_password_history", 24)

    test = Test(
        test_id=test_id,
        test_description=(
            f"IAM passwords must comply with the organizations password complexity requirements."
        ),      
        test_procedures=[
            "Obtained the IAM password configuration by calling the get_account_password_policy() boto3 command.",
            "Saved the AWS password policy: iam/password_policy.json.",
            "Inspected the password configuration to determine if they comply with the test attribute(s) defined below."
        ],
        test_attributes=[
            f"MinimumPasswordLength must be >= {required_min_length}.",
            f"At least {req_min_complexity_types} complexity types (RequireSymbols, RequireNumbers, "
            "RequireUppercaseCharacters, and RequireLowercaseCharacters) are set to True.",
            f"PasswordReusePrevention must be >= {required_password_history}."
        ],
        risk_rating=risk_rating
    )

    policy = audit.evidence_client.get_aws(
        "iam/password_policy.json",
        service="iam",
        method="get_account_password_policy",
        not_found_codes=["NoSuchEntity"]
    )

    if not policy:
        test.is_passing = False
        test.comments = "Exceptions Noted. No password policy configured."
        return test

    password_policy = policy.get("PasswordPolicy", {})
    failures = []
    # Test password minimum length
    actual_min_length = password_policy.get("MinimumPasswordLength", 0)
    if actual_min_length < required_min_length:
        failures.append(
            f"Minimum password length too short (current={actual_min_length}, required>={required_min_length})"
        )

    # Test password complexity requirements
    complexity_flags = [
        password_policy.get("RequireSymbols", False),
        password_policy.get("RequireNumbers", False),
        password_policy.get("RequireUppercaseCharacters", False),
        password_policy.get("RequireLowercaseCharacters", False),
    ]
    actual_num_complexity_types = sum(complexity_flags)
    if actual_num_complexity_types < req_min_complexity_types:
        failures.append(
            f"Not enough complexity types enabled (current={actual_num_complexity_types}/4, required>={req_min_complexity_types}/4)"
        )

    # Test password history (number of passwords remembered by AWS)
    actual_password_history = password_policy.get("PasswordReusePrevention", 0)
    if actual_password_history < required_password_history:
        failures.append(
            f"Password history too small (current={actual_password_history}, required>={required_password_history})"
        )

    # Test password expiration, if required by config.json
    required_expiration = test_config.get("iam_password_require_expiration", False)
    if required_expiration:
        required_max_password_age = test_config.get("iam_password_max_password_age", 365)        
        expire_enabled = password_policy.get("ExpirePasswords", False)
        actual_max_password_age = password_policy.get("MaxPasswordAge")
        # Add password expiration as test attribute.
        test.test_attributes.append(
            f"Passwords must expire within {required_max_password_age} days."
        )
        if not expire_enabled:
            failures.append("Password expiration is not enabled.")
        elif actual_max_password_age is None:
            failures.append("Max password age is not set.")
        elif actual_max_password_age > required_max_password_age:
            failures.append(
                f"Password max age too high (current={actual_max_password_age}, required<={required_max_password_age}.)"
            )

    # --- Document conclusion ---
    test.is_passing = len(failures) == 0
    if not test.is_passing:
        test.comments = "; ".join(failures)
        test.comments = "Exceptions Noted. " + test.comments
    return test

def test_iam_root_access_key(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="Root account does not have any active access keys.",      
        test_procedures=[
            "Obtained the AWS account summary by calling the get_account_summary() boto3 command.",
            "Saved the account summary: iam/account_summary.json.",
            "Inspected the account summary to determine if 'AccountAccessKeysPresent' is set to 0."
        ],
        test_attributes=[],
        risk_rating = risk_rating
    )

    summary = audit.evidence_client.get_aws(
        "iam/account_summary.json",
        service="iam",
        method="get_account_summary"
    )

    account_summary = summary.get("SummaryMap", {})
    root_keys = account_summary.get("AccountAccessKeysPresent", 0)

    if root_keys == 0:
        test.is_passing = True
    else:
        test.is_passing = False
        test.comments = f"Exceptions Noted. Root account has {root_keys} access key(s)"

    return test

def test_iam_root_mfa(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="Root account has MFA enabled.",
        test_procedures=[
            "Obtained the AWS account summary by calling the get_account_summary() boto3 command.",
            "Saved the account summary: iam/account_summary.json",
            "Inspected the account summary to determine if 'AccountMFAEnabled' is set to 1."
        ],
        test_attributes=[],
        risk_rating=risk_rating
    )

    iam = audit.session.client("iam")
    summary = audit.evidence_client.get_aws(
        "iam/account_summary.json",
        service="iam",
        method="get_account_summary"
    )

    account_summary = summary.get("SummaryMap", {})
    mfa_enabled = account_summary.get("AccountMFAEnabled", 0)

    if mfa_enabled == 1:
        test.is_passing = True
    else:
        test.is_passing = False
        test.comments = "Exceptions Noted. Root account does not have MFA enabled."
        
    return test

def test_iam_users_mfa(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="IAM users with an active console password have MFA enabled.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of IAM users: iam/users.json.",
            "For each IAM user, obtained the login profile information by calling the get_login_profile() boto3 command.",
            "For each IAM user, saved the login profile: iam/users/[user_name]/login_profile.json.",
            "Saved the login profile for each user in the audit evidence folder (iam/users/[user_name]/login_profile.json).",
            "For each IAM user with a login profile, obtained the MFA device information by calling the list_mfa_devices() boto3 command.",
            "For each IAM user with a login profile, saved the MFA device information: iam/users/[user_name]/mfa_devices.json]",
            "For each IAM user with a login profile, inspected mfa_devices.json to determine if at least one MFA device is registered."
        ],
        test_attributes=[],
        table_headers=["IAM User Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    users = audit.evidence_client.get_aws(
            "iam/users.json",
            service="iam",
            paginator_params={
                "method_name": "list_users",
                "pagination_key": "Users"
            }
    )

    for user in users.get("Users", []):
        username = user["UserName"]
        sample = Sample(sample_id={"user": username})
        if sample.check_excluded(test, audit):
            continue

        # Check if user has a console password
        login_profile = audit.evidence_client.get_aws(
            f"iam/users/{username}/login_profile.json",
            service="iam",
            method="get_login_profile",
            method_kwargs={"UserName": username},
            not_found_codes=["NoSuchEntity"]
        )

        # No response or explicitly empty response
        if not login_profile:
            sample.is_passing = True
            sample.comments = "User has no console password (programmatic access only)."
            test.samples.append(sample)
            continue

        # Response exists but no login profile inside it
        if not login_profile.get("LoginProfile"):
            sample.is_passing = True
            sample.comments = "User has no console password (programmatic access only)."
            test.samples.append(sample)
            continue

        # Check MFA devices
        mfa_devices = (
            audit.evidence_client.get_aws(
                f"iam/users/{username}/mfa_devices.json",
                service="iam",
                method="list_mfa_devices",
                method_kwargs={"UserName": username}
            ) or {}
        ).get("MFADevices", [])

        if len(mfa_devices) > 0:
            sample.is_passing = True
        else:
            sample.comments = "No MFA device enabled for this user."

        test.samples.append(sample)

    test.evaluate_samples()

    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} IAM user(s) do not have MFA enabled."
        )

    return test

def test_iam_user_access_key_age(audit, test_id, risk_rating=3):
    test_config = audit.config.get("test_config") or {}
    max_age_days = test_config.get("iam_key_max_age", 90)

    test = Test(
        test_id=test_id,
        test_description=f"IAM user access keys are rotated at least every {max_age_days} days.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of IAM users: iam/users.json.",
            "For each IAM user, obtained access key metadata by calling the list_access_keys() boto3 command.",
            "For each IAM user, saved access key metadata: iam/users/[user_name]/access_keys.json",
            "Inspected the 'AccessKeyMetadata' for each user to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=[
            f"'CREATE_DATE <= {max_age_days} days ago (for keys with an 'ACTIVE' status)."
        ],
        table_headers=["User", "Access Key ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    users = audit.evidence_client.get_aws(
            "iam/users.json",
            service="iam",
            paginator_params={
                "method_name": "list_users",
                "pagination_key": "Users"
            }
    )

    now = datetime.now(timezone.utc)

    for user in users.get("Users", []):
        username = user["UserName"]

        keys = audit.evidence_client.get_aws(
            f"iam/users/{username}/access_keys.json",
            service="iam",
            method="list_access_keys",
            method_kwargs={"UserName": username}
        ) 

        for key in keys.get("AccessKeyMetadata", []):
            sample = Sample(
                sample_id={
                    "user": username,
                    "access_key_id": key["AccessKeyId"]
                }
            )
            if sample.check_excluded(test, audit):
                continue

            if key["Status"] != "Active":
                sample.is_excluded = True
                sample.comments = "N/A - key is inactive."
                test.samples.append(sample)
                continue

            create_date = key["CreateDate"]

            if isinstance(create_date, str):
                create_date = create_date.replace("Z", "+00:00")
                create_date = datetime.fromisoformat(create_date)

            actual_age_days = (now - create_date).days

            if actual_age_days <= max_age_days:
                sample.is_passing = True
            else:
                sample.comments = f"Key is {actual_age_days} days old."

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} IAM key(s) are over {max_age_days} days old."
    return test


def test_rds_encryption(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="RDS instances are encrypted at rest.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: rds/region_name/db_instances.json.",
            "For each RDS instance, inspected the `StorageEncrypted` setting to determine if it was set to `true`."
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    for region in audit.in_scope_regions:
        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            if db.get("StorageEncrypted"):
                sample.is_passing = True
            else:
                sample.comments = "RDS instance is not encrypted."

            test.samples.append(sample)
    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} RDS instance(s) are not encrypted."
    return test

def test_rds_public_access(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="RDS instances are not publicly accessible.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: rds/[region_name]/db_instances.json)",
            "For each RDS instance, inspected the 'PubliclyAccessible' setting to determine if it was set to 'false'."
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    for region in audit.in_scope_regions:
        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            if not db.get("PubliclyAccessible", False):
                sample.is_passing = True
            else:
                sample.comments = "Instance is publicly accessible."

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} RDS instance(s) are publicly accessible."
    return test

def test_rds_tags(audit, test_id, risk_rating=1):
    # Get base required tags.
    test_config = audit.config.get("test_config") or {}
    base_required_tags = test_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'rds_required_tags' is set
    required_tags = test_config.get("rds_required_tags", base_required_tags)

    test = Test(
        test_id=test_id,
        test_description=(
            "RDS instances must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: rds/[region_name]/db_instances.json).",
            f"For each RDS instance, reviewed the `TagList` to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            actual_db_tags = {t["Key"]: t.get("Value", "") for t in db.get("TagList", [])}
            evaluate_tags(sample, required_tags, actual_db_tags)
            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} RDS instance(s) are missing required tags or have empty values."
        )

    return test

def test_rds_backup_retention(audit, test_id, risk_rating=1):
    test_config = audit.config.get("test_config") or {}
    required_rds_retention_days = test_config.get("rds_backup_retention_days", 14)
    test = Test(
        test_id=test_id,
        test_description=f"RDS backups are retained for at least {required_rds_retention_days} days.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: rds/[region_name]/db_instances.json.",
            f"For each RDS instance, inspected the `BackupRetentionPeriod` to determine if it is greater than or equal to {required_rds_retention_days} days."
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            actual_retention_days = db.get("BackupRetentionPeriod", 0)

            if actual_retention_days >= required_rds_retention_days:
                sample.is_passing = True
            else:
                sample.comments = f"Retention is {actual_retention_days} days"

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        # Document exception language.
        test.comments = f"Exceptions Noted. {test.num_findings} RDS instance(s) do not retain backups for at least {required_rds_retention_days} days."
    return test

def test_rds_auto_minor_version_upgrade(audit, test_id, risk_rating=1):
    test = Test(
        test_id=test_id,
        test_description="RDS instances have automatic minor version upgrades enabled.",
        test_procedures=[
            "For each in-scope region, obtained a list of DB instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: rds/[region_name]/db_instances.json.",
            "For each RDS instance, inspected the 'AutoMinorVersionUpgrade' setting to determine if it was set to 'true'."
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            if db.get("AutoMinorVersionUpgrade"):
                sample.is_passing = True
            else:
                sample.comments = "Automatic minor version upgrades are not enabled."

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} RDS instance(s) do not have automatic minor version upgrades enabled."
        )

    return test

def test_rds_deletion_protection(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="RDS instances have deletion protection enabled at the cluster or instance level.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances and RDS clusters using describe_db_instances() and describe_db_clusters() boto3 commands.",
            "Saved the list of RDS instances: rds/[region_name]/db_instances.json and DB clusters: rds/[region_name]/db_clusters.json.",
            "Inspected each RDS instance to determine if 'DeletionProtection' was set to 'true' at the instance or cluster level."
        ],
        test_attributes=[],
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    for region in audit.in_scope_regions:
        # Get DB instances
        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_instances.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        # Get DB clusters
        instances = audit.evidence_client.get_aws(
            f"rds/{region}/db_clusters.json",
            service="rds",
            region=region,
            paginator_params={
                "method_name": "describe_db_clusters",
                "pagination_key": "DBClusters"
            }
        )

        # Build lookup for cluster deletion protection
        cluster_map = {
            c["DBClusterIdentifier"]: c.get("DeletionProtection", False)
            for c in clusters.get("DBClusters", [])
        }

        for db in instances.get("DBInstances", []):
            sample = Sample(sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]})
            if sample.check_excluded(test, audit):
                continue

            instance_protection = db.get("DeletionProtection", False)
            cluster_id = db.get("DBClusterIdentifier")
            # Check if deletion protection is enabled at the cluster level.
            if cluster_id:
                cluster_protection = cluster_map.get(cluster_id, False)
            else:
                cluster_protection = False

            # Pass if either instance OR cluster has deletion protection
            if instance_protection or cluster_protection:
                sample.is_passing = True
            else:
                if cluster_id:
                    sample.comments = "Deletion protection is not enabled at either the instance or cluster level."
                else:
                    sample.comments = "Deletion protection is not enabled at the instance level."
            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} RDS instance(s) do not have deletion protection enabled."
        )

    return test

def test_ec2_security_group_tags(audit, test_id, risk_rating=1):
    # Get required tags.
    test_config = audit.config.get("test_config") or {}
    required_tags = test_config.get("ec2_sg_required_tags", ["Owner", "Description", "ReviewedBy", "LastReviewedDate"])

    test = Test(
        test_id=test_id,
        test_description=(
            "EC2 security groups have required tags applied and tag values are not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained a list of EC2 security groups by calling describe_security_groups() boto3 command.",
            "For each in-scope region, saved the list of security groups: ec2/[region]/security_groups.json",
            f"Inspected each security group's 'Tags' attribute to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Region", "Security Group ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        security_groups = audit.evidence_client.get_aws(
            f"ec2/{region}/security_groups.json",
            service="ec2",
            region=region,
            paginator_params={
                "method_name": "describe_security_groups",
                "pagination_key": "SecurityGroups"
            }
        )  

        for sg in security_groups.get("SecurityGroups", []):
            sample = Sample(sample_id={"region": region, "security_group_id": sg["GroupId"]})
            if sample.check_excluded(test, audit):
                continue

            # Security group tags
            actual_sg_tags = {
                t["Key"]: t.get("Value", "")
                for t in sg.get("Tags", [])
            }

            evaluate_tags(sample, required_tags, actual_sg_tags)
            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} security group(s) are missing required tags or have empty values."
        )

    return test

def test_ec2_tags(audit, test_id, risk_rating=1):
    # Get base required tags.
    test_config = audit.config.get("test_config") or {}
    base_required_tags = test_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'ec2_required_tags' is set
    required_tags = test_config.get("ec2_required_tags", base_required_tags)

    test = Test(
        test_id=test_id,
        test_description=(
            "EC2 instances must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of EC2 instances by calling describe_instances() boto3 command.",
            "For each in-scope AWS region, saved the list of EC2 instances: ec2/[region_name]/instances.json",
            f"For each EC2 instance, reviewed the 'Tags' to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Region", "Instance ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"ec2/{region}/instances.json",
            service="ec2",
            region=region,
            paginator_params={
                "method_name": "describe_instances",
                "pagination_key": "Reservations"
            }
        )

        for reservation in instances.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                sample = Sample(sample_id={"region": region, "instance_id": instance["InstanceId"]})
                if sample.check_excluded(test, audit):
                    continue

                # EC2 tags come in the 'Tags' attribute
                instance_tags = {
                    t["Key"]: t.get("Value", "")
                    for t in instance.get("Tags", [])
                }

                evaluate_tags(sample, required_tags, instance_tags)
                test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} EC2 instance(s) are missing required tags or have empty values."
        )

    return test

def test_ebs_volume_encryption(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="EBS volumes are encrypted at rest.",
        test_procedures=[
            "For each in-scope region, obtained a list of EBS volumes by calling describe_volumes() boto3 command.",
            "For each in-scope region, saved the list of EBS volumes: ec2/[region_name]/volumes.json.",
            "For each EBS volume, inspected the 'Encrypted' attribute to determine it is set to 'true'."
        ],
        test_attributes=[],
        table_headers=["Region", "Volume ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        volumes = audit.evidence_client.get_aws(
            f"ec2/{region}/volumes.json",
            service="ec2",
            region=region,
            paginator_params={
                "method_name": "describe_volumes",
                "pagination_key": "Volumes"
            }
        )

        for volume in volumes.get("Volumes", []):
            sample = Sample(sample_id={"region": region, "volume_id": volume["VolumeId"]})
            if sample.check_excluded(test, audit):
                continue

            if volume.get("Encrypted"):
                sample.is_passing = True
            else:
                sample.comments = "EBS volume is not encrypted."

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} EBS volume(s) are not encrypted."
        )

    return test

def test_ebs_tags(audit, test_id, risk_rating=1):
    # Get base required tags.
    test_config = audit.config.get("test_config") or {}
    base_required_tags = test_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'ebs_required_tags' is set
    required_tags = test_config.get("ebs_required_tags", base_required_tags)

    test = Test(
        test_id=test_id,
        test_description=(
            "EBS volumes must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of EBS volumes by calling describe_volumes() boto3 command.",
            "Saved the list of volumes in the audit evidence folder (ec2/[region_name]/volumes.json).",
            "For each volume, obtained its tags from the 'Tags' attribute.",
            f"Inspected each EBS volume to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Region", "Volume ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        volumes = audit.evidence_client.get_aws(
            f"ec2/{region}/volumes.json",
            service="ec2",
            region=region,
            paginator_params={
                "method_name": "describe_volumes",
                "pagination_key": "Volumes"
            }
        )

        for volume in volumes.get("Volumes", []):
            sample = Sample(sample_id={"region": region, "volume_id": volume["VolumeId"]})
            if sample.check_excluded(test, audit):
                continue

            # EBS tags come in the 'Tags' attribute
            volume_tags = {t["Key"]: t.get("Value", "") for t in volume.get("Tags", [])}

            # Reuse helper to evaluate tags
            evaluate_tags(sample, required_tags, volume_tags)

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} EBS volume(s) are missing required tags or have empty values."
        )

    return test

def test_ebs_default_encryption(audit, test_id, risk_rating=0):
    # NOTE: Risk rating is set to 'Informational'. Not having this set does not mean there are unencrypted EBS volumes.
    test = Test(
        test_id=test_id,
        test_description="EBS volumes must have default encryption enabled in each region.",
        test_procedures=[
            "For each in-scope region, obtained the EBS default encryption settings by calling get_ebs_encryption_by_default() boto3 command.",
            "For each in-scope region, saved the EBS default encryption settings: ec2/[region_name]/default_ebs_encryption.json.",
            "Inspected the configuration for each region to determine if 'EbsEncryptionByDefault' is set to True."
        ],
        test_attributes=[],
        table_headers=["Region", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        default_encryption = audit.evidence_client.get_aws(
            f"ec2/{region}/default_ebs_encryption.json",
            service="ec2",
            region=region,
            method="get_ebs_encryption_by_default"
        )   

        sample = Sample(sample_id={"region": region})
        if sample.check_excluded(test, audit):
            continue

        if default_encryption.get("EbsEncryptionByDefault"):
            sample.is_passing = True
        else:
            sample.comments = "EBS default encryption is not enabled in this region."

        test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} region(s) do not have EBS default encryption enabled."
        )

    return test

def test_lambda_tags(audit, test_id, risk_rating=1):
    # Get base required tags.
    test_config = audit.config.get("test_config") or {}
    base_required_tags = test_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'lambda_required_tags' is set
    required_tags = test_config.get("lambda_required_tags", base_required_tags)

    test = Test(
        test_id=test_id,
        test_description=(
            "Lambda functions must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of Lambda functions by calling list_functions() boto3 command.",
            "Saved the list of functions in the audit evidence folder (lambda/[region_name]/functions.json).",
            "For each function, obtained its tags using list_tags() boto3 command.",
            "Saved the tags for each function in the audit evidence folder (lambda/[region_name]/functions/[function_name]/tags.json).",
            f"Inspected each Lambda function to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        table_headers=["Region", "Function Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        functions = audit.evidence_client.get_aws(
            f"lambda/{region}/functions.json",
            service="lambda",
            region=region,
            paginator_params={
                "method_name": "list_functions",
                "pagination_key": "Functions"
            }
        )

        for fn in functions.get("Functions", []):
            function_name = fn["FunctionName"]
            sample = Sample(sample_id={"region": region, "function_name": function_name})
            if sample.check_excluded(test, audit):
                continue

            # Fetch tags via ARN
            arn = fn.get("FunctionArn")
            tags_response = audit.evidence_client.get_aws(
                f"lambda/{region}/functions/{function_name}/tags.json",
                service="lambda",
                region=region,
                method="list_tags",
                method_kwargs={"Resource": arn}
            )

            lambda_tags = tags_response.get("Tags", {})
            evaluate_tags(sample, required_tags, lambda_tags)
            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} Lambda function(s) are missing required tags or have empty values."
        )

    return test

def test_cloudtrail_multi_region(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="At least one multi-region CloudTrail trail has logging enabled.",
        test_procedures=[
            "Obtained a list of CloudTrail trails by calling the describe_trails() boto3 command.",
            "Saved the list of CloudTrail trails: cloudtrail/trails.json.",
            "For each CloudTrail trail, inspected the trail configuration to determine whether 'IsMultiRegionTrail' is set to 'true'.",
            "For each multi-region trail, obtained the trail status by calling the get_trail_status() boto3 command.",
            "For each multi-region trail, saved the trail status: cloudtrail/trails/[trail_name]/trail_status.json.",
            "Inspected the trail configuration and status to determine if at least one trail complies with the test attribute(s) defined below."
        ],
        test_attributes=[
            "At least one trail must have IsMultiRegionTrail = true and IsLogging = true."
        ],
        risk_rating=risk_rating
    )

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "cloudtrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        test.is_passing = False
        test.comments = "Exceptions Noted. No CloudTrail trail was found."
        return test

    found_valid_trail = False
    for trail in trails:
        if not trail.get("IsMultiRegionTrail", False):
            continue
        status = audit.evidence_client.get_aws(
            f"cloudtrail/trails/{trail['Name']}/trail_status.json",
            lambda: ct.get_trail_status(Name=trail["TrailARN"])
        )
        if status.get("IsLogging", False):
            found_valid_trail = True
            break

    if found_valid_trail:
        test.is_passing = True
    else:
        test.is_passing = False
        test.comments = (
            "Exceptions Noted. No multi-region CloudTrail trail with active logging was found."
        )

    return test

def test_cloudtrail_log_file_validation(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="CloudTrail trails have log file validation enabled.",
        test_procedures=[
            "Obtained CloudTrail trails using the describe_trails() boto3 command.",
            "Saved the trail configuration in the audit evidence folder (cloudtrail/trails.json).",
            "Inspected each trail's configuration to determine if 'LogFileValidationEnabled' was set to True for all trails."
        ],
        test_attributes=[],
        table_headers=["Trail Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "cloudtrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        test.is_passing = False
        test.comments = "Exceptions Noted. No CloudTrail trails are configured."
        return test

    for trail in trails:
        trail_name = trail["Name"]
        sample = Sample(sample_id={"trail_name": trail_name})
        if sample.check_excluded(test, audit):
            continue

        log_validation = trail.get("LogFileValidationEnabled", False)
        if log_validation:
            sample.is_passing = True
        else:
            sample.comments = "Log file validation is disabled."
        test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} trail(s) do not have log file validation enabled."
        )

    return test

def test_cloudtrail_s3_bucket_protection(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="CloudTrail S3 buckets are configured to block public access.",
        test_procedures=[
            "Obtained a list of CloudTrails by calling the describe_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (cloudtrail/trails.json).",
            "For each trail, obtained the S3 bucket name and checked the bucket's public access block settings using get_public_access_block() boto3 command.",
            "Saved the public access block settings for each bucket in the audit evidence folder (s3/buckets/[bucket_name]/public_access_block.json).",
            "Inspected the public access block settings for each S3 bucket containing CloudTrail logs to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=[
            "CloudTrail S3 buckets must block public access (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets = True)."
        ],
        table_headers=["Trail Name", "Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "cloudtrail/trails.json",
        lambda: ct.describe_trails()
    ).get("trailList", [])

    for trail in trails:
        trail_name = trail.get("Name")
        bucket_name = trail.get("S3BucketName")

        sample = Sample(sample_id={"trail_name": trail_name, "bucket_name": bucket_name})
        if sample.check_excluded(test, audit):
            continue

        if not bucket_name:
            sample.comments = "Trail does not have an associated S3 bucket."
            test.samples.append(sample)
            continue

        # Fetch public access block
        public_access_block = audit.evidence_client.get_aws(
            f"s3/buckets/{bucket_name}/public_access_block.json",
            lambda: audit.session.client("s3").get_public_access_block(Bucket=bucket_name),
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )

        if not public_access_block:
            sample.comments = "No Public Access Block configuration found."
            test.samples.append(sample)
            continue

        config = public_access_block.get("PublicAccessBlockConfiguration", {})
        block_acls = config.get("BlockPublicAcls", False)
        ignore_acls = config.get("IgnorePublicAcls", False)
        block_policy = config.get("BlockPublicPolicy", False)
        restrict_buckets = config.get("RestrictPublicBuckets", False)

        # Document conclusion
        if all([block_acls, ignore_acls, block_policy, restrict_buckets]):
            sample.is_passing = True
        else:
            sample.comments = "One or more public access settings are not enabled."

        test.samples.append(sample)

    test.evaluate_samples()

    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} CloudTrail bucket(s) are not blocking public access."
        )

    return test

"""
    Ensure CloudTrail logging has not been stopped within the configured lookback period.
"""
def test_cloudtrail_logging_recent_stops(audit, test_id, risk_rating=3):
    test_config = audit.config.get("test_config") or {}
    lookback_days = test_config.get("cloudtrail_logging_lookback_days", 365)

    test = Test(
        test_id=test_id,
        test_description=(
            f"CloudTrail logging has not been stopped in the last {lookback_days} days."
        ),
        test_procedures=[
            "Obtained a list of CloudTrails by calling the describe_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (cloudtrail/trails.json).",
            "For each trail, called get_trail_status() to check IsLogging and StopLoggingTime.",
            f"Saved each trail's status in the audit evidence folder (cloudtrail/trails/[trail_name]/trail_status.json).",
            f"Inspected the 'TimeLoggingStopped' variable to determine if logging has been stopped in the last {lookback_days} days."
        ],
        test_attributes=[
            f"'TimeLoggingStopped' must be empty OR is more than {lookback_days} days ago."
        ],
        table_headers=["Trail Name", "Is Logging", "Last Stop Time", "Result", "Comments"],
        risk_rating=risk_rating
    )

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "cloudtrail/trails.json",
        lambda: ct.describe_trails()
    ).get("trailList", [])

    now = datetime.now(timezone.utc)
    lookback_threshold = now - timedelta(days=lookback_days)

    for trail in trails:
        trail_name = trail.get("Name")
        sample = Sample(sample_id={"trail_name": trail_name})
        if sample.check_excluded(test, audit):
            continue

        status = audit.evidence_client.get_aws(
            f"cloudtrail/trails/{trail_name}/trail_status.json",
            lambda: ct.get_trail_status(Name=trail_name)
        )

        is_logging = status.get("IsLogging", False)
        stop_time = status.get("StopLoggingTime")

        # Convert StopLoggingTime to datetime if present
        if stop_time:
            if isinstance(stop_time, str):
                stop_time = datetime.fromisoformat(stop_time.replace("Z", "+00:00"))

        # Document conclusion
        if not is_logging:
            sample.is_passing = False
            sample.comments = "CloudTrail logging is currently stopped."
        elif stop_time and stop_time >= lookback_threshold:
            sample.is_passing = False
            sample.comments = f"Logging was stopped recently on {stop_time.isoformat()}."
        else:
            sample.is_passing = True

        test.samples.append(sample)

    test.evaluate_samples()

    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} trail(s) are not currently logging or have been stopped "
            f"within the last {lookback_days} days."
        )

    return test

def test_wafv2_enabled(audit, test_id, risk_rating=2):
    test = Test(
        test_id=test_id,
        test_description="WAF is enabled on Application Load Balancers and API Gateways.",
        test_procedures=[
            "For each in-scope region, obtained a list of Web ACLs by calling list_web_acls() boto3 command.",
            "Saved the list of Web ACLs (wafv2/[region]/web_acls.json).",
            "For each Web ACL, obtained a list of associated resources by calling the list_resources_for_web_acl() boto3 command.",
            "By default the list_resources_for_web_acl() only provide a list of Application Load Balancers.",
            "Saved the Application Load Balancers associated with the ACL (wafv2/[region]/[web_acl_name]/resources.json).",
            "Re-ran the list_resources_for_web_acl() boto3 command to get the associated API Gateways.",     
            "For each in-scope region, obtained a list of Application Load Balancers using describe_load_balancers() boto3 command.",
            "Saved the list of load balancers in the audit evidence folder (elbv2/[region_name]/load_balancers.json).",
            "For each load balancer, checked if Load Balancer ARN was associated with a Web ACL.",
            "For each in-scope region, obtained a list of API Gateways using get_rest_apis() boto3 command.",
            "Saved the list of API Gateways in the audit evidence folder (apigateway/[region_name]/rest_apis.json).",
            "For each API gateway to check if it was associated with a Web ACL."
        ],
        test_attributes=[],
        table_headers=["Region", "Resource Type", "Resource ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        waf = audit.session.client("wafv2", region_name=region)
        elbv2 = audit.session.client("elbv2", region_name=region)
        apigw = audit.session.client("apigateway", region_name=region)

        # Get list of Web ACLs (REGIONAL scope for ALB + API Gateway)
        web_acls = audit.evidence_client.get_aws(
            f"wafv2/{region}/web_acls.json",
            lambda: waf.list_web_acls(Scope="REGIONAL")
        )

        # Preload WAF information
        acl_to_alb_resources = {}
        acl_to_api_resources = {}

        for acl in web_acls.get("WebACLs", []):
            web_acl_arn = acl["ARN"]
            # ALBs
            alb_resources = audit.evidence_client.get_aws(
                f"wafv2/{region}/{acl['Name']}/resources_alb.json",
                lambda: waf.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceType="APPLICATION_LOAD_BALANCER"
                )
            )
            acl_to_alb_resources[web_acl_arn] = set(alb_resources.get("ResourceArns", []))

            # API Gateway
            api_resources = audit.evidence_client.get_aws(
                f"wafv2/{region}/{acl['Name']}/resources_apigw.json",
                lambda: waf.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceType="API_GATEWAY"
                )
            )
            acl_to_api_resources[web_acl_arn] = set(api_resources.get("ResourceArns", []))        

        # ALBs
        lbs = audit.evidence_client.get_aws(
            f"elbv2/{region}/load_balancers.json",
            fetch_fn=None,
            paginator_params={
                "client": elbv2,
                "method_name": "describe_load_balancers",
                "pagination_key": "LoadBalancers"
            }
        )

        for lb in lbs.get("LoadBalancers", []):
            if lb.get("Type") != "application":
                continue  # Only ALBs

            sample = Sample(
                sample_id={
                    "region": region,
                    "resource_type": "ALB",
                    "resource_id": lb["LoadBalancerName"]
                }
            )
            if sample.check_excluded(test, audit):
                continue

            lb_arn = lb.get("LoadBalancerArn")
            if not lb_arn:
                continue
            alb_attached = False

            alb_attached = any(
                lb_arn in resource_set
                for resource_set in acl_to_alb_resources.values()
            )

            if alb_attached:
                sample.is_passing = True
            else:
                sample.comments = "No WAF Web ACL associated."

            test.samples.append(sample)

        # API Gateway (REST APIs)
        apis = audit.evidence_client.get_aws(
            f"apigateway/{region}/rest_apis.json",
            lambda: apigw.get_rest_apis()
        )

        for api in apis.get("items", []):
            sample = Sample(
                sample_id={
                    "region": region,
                    "resource_type": "API Gateway",
                    "resource_id": api["id"]
                }
            )

            if sample.check_excluded(test, audit):
                continue
            
            api_gw_arn = f"arn:aws:apigateway:{region}::/restapis/{api['id']}"
            api_gw_attached = any(
                any(r.startswith(api_gw_arn) for r in resource_set)
                for resource_set in acl_to_api_resources.values()
            )

            if api_gw_attached:
                sample.is_passing = True
            else:
                sample.comments = "No WAF Web ACL associated."

            test.samples.append(sample)

    test.evaluate_samples()
    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. {test.num_findings} resource(s) do not have WAF enabled."
        )

    return test

def test_guardduty_enabled(audit, test_id, risk_rating=3):
    test = Test(
        test_id=test_id,
        test_description="GuardDuty is enabled for all in-scope regions.",
        test_procedures=[
            "For each in-scope region, obtained a list of GuardDuty detectors by calling the list_detectors() boto3 command.",
            "For each in-scope region, saved the list of detector IDs: guardduty/[region]/detectors.json.",
            "For each detector ID, obtained detector configuration by calling the get_detector() boto3 command.",
            "For each detector ID, saved the detector configuration: guardduty/[region]/[detector_id]/config.json.",
            "For each detector ID, inspected the detector configuration to determine whether 'Status' is set to 'ENABLED'."
        ],
        test_attributes=[],
        table_headers=["Region", "Result", "Comments"],
        risk_rating=risk_rating
    )

    for region in audit.in_scope_regions:
        gd = audit.session.client("guardduty", region_name=region)

        sample = Sample(sample_id={"region": region})
        if sample.check_excluded(test, audit):
            continue

        detectors = audit.evidence_client.get_aws(
            f"guardduty/{region}/detectors.json",
            lambda: gd.list_detectors()
        ).get("DetectorIds", [])

        if not detectors:
            sample.is_passing = False
            sample.comments = "No GuardDuty detectors in region."
            test.samples.append(sample)
            continue

        enabled_detector_found = False

        for detector_id in detectors:
            config = audit.evidence_client.get_aws(
                f"guardduty/{region}/{detector_id}/config.json",
                lambda: gd.get_detector(DetectorId=detector_id)
            )

            if config.get("Status") == "ENABLED":
                enabled_detector_found = True
                break

        if enabled_detector_found:
            sample.is_passing = True
        else:
            sample.is_passing = False
            sample.comments = "Detector(s) found but none are enabled."

        test.samples.append(sample)

    test.evaluate_samples()

    if not test.is_passing:
        test.comments = (
            f"Exceptions Noted. GuardDuty is not enabled for {test.num_findings} in-scope region(s)."
        )

    return test
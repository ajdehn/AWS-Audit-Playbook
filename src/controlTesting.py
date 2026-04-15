from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from utils import is_control_excluded, process_sample_exclusion, evaluate_tags, save_json
import boto3
import botocore
from datetime import datetime, timezone, timedelta
import traceback
import json

# NOTE: Sample results are set to "False" until logic determines sample passes the testing criteria.
@dataclass
class Sample:
    sample_id: Dict[str, Any]
    control_id: str
    result: bool = False
    is_excluded: bool = False
    comments: str = ""

    def __str__(self):
        return (
            f"sample_id: {self.sample_id}\n"
            f"result: {self.result}\n"
            f"comments: {self.comments}\n"
        )

# NOTE: Control results are set to "True" until an invalid control is identified.
@dataclass
class Control:
    control_id: str
    control_description: str
    test_procedures: List[str]
    test_attributes: List[str]
    audit: Audit
    # Rating Matrix: 0 - Informational, 1 - Low, 2 - Medium, 3 - High.
    risk_rating: int    
    table_headers: Optional[List[str]] = None
    include_sample_number: bool = False
    samples: List["Sample"] = field(default_factory=list)
    result: bool = True
    result_description: str = ""
    num_findings: int = 0
    num_exclusions: int = 0
    total_population: int = 0
    is_excluded: bool = False
    risk_rating_str: str = ""

    def __post_init__(self):
        self.risk_rating_str = self.create_risk_str()
        # Set exclusion status AFTER object is created
        self.is_excluded = is_control_excluded(
            self.control_id,
            self.audit.config
        )

        if self.is_excluded:
            self.result_description = "Control is excluded. See exclusions.json"

    def __str__(self):
        return (
            f"control_id: {self.control_id}\n"
            f"control_description: {self.control_description}\n"
            f"risk_rating: {self.risk_rating}\n"
            f"is_excluded: {self.is_excluded}\n"
            f"result: {'Pass' if self.result else 'Fail'}\n"
            f"result_description: {self.result_description}\n"
        )

    def to_dict(self):
        return {
            "control_id": self.control_id,
            "control_description": self.control_description,
            "risk_rating": self.risk_rating,
            "is_excluded": self.is_excluded,
            "result": "Pass" if self.result else "Fail",
            "result_description": self.result_description,
            "test_procedures": self.test_procedures,
            "test_attributes": self.test_attributes
        }

    def create_risk_str(self):
        if self.risk_rating == 0: return "Informational"
        elif self.risk_rating == 1: return "Low"
        elif self.risk_rating == 2: return "Medium"
        elif self.risk_rating == 3: return "High"
        else:
            raise ValueError(f"Invalid risk rating: {self.risk_rating}. Accepted values are 0 - 3.")

    def evaluate_samples(self):
        if self.is_excluded:
            self.result = False
            self.num_findings = 0
            self.total_population = 0
            self.num_exclusions = 0
            return self

        # Determine total population (includes pass, fail, and exclusions)
        self.total_population = len(self.samples)

        # Count exclusions first
        self.num_exclusions = sum(1 for s in self.samples if s.is_excluded)

        # Filter in-scope samples
        in_scope_samples = [s for s in self.samples if not s.is_excluded]

        if not in_scope_samples:
            # No valid samples. Control passes with a population of zero.
            self.result = True
            return self

        # Count findings (failures)
        self.num_findings = sum(1 for s in in_scope_samples if not s.result)

        # Final result
        self.result = self.num_findings == 0
        return self


def run_control_safely(audit, control_fn, control_id):
    try:
        return control_fn(audit, control_id)
    except Exception as e:

        print(f"\nERROR running control: {control_id}")
        print(f"Exception: {e}\n")
        traceback.print_exc()

        # Create a failed control object
        control = Control(
            control_id=control_id,
            control_description=f"{control_id} (Execution Failed)",
            test_procedures=["Control execution failed."],
            test_attributes=[],
            audit=audit,
            table_headers=["Error"],
            risk_rating=3
        )
        control.result = False
        control.result_description = f"Control execution failed. Please manually investigate."
        print(f"ERROR: Running {control_id} test failed. Moving to the next test.")

        return control

def run_all_tests(audit):
    control_definitions = [
        ("IAM Root MFA", test_root_mfa_enabled),
        ("IAM Root Access Key", test_root_no_access_keys),
        ("IAM User MFA", test_iam_users_mfa),
        ("IAM User Key Age", test_iam_access_key_age),
        ("IAM Password", test_iam_password_policy),
        ("S3 Encryption", test_s3_encryption),
        ("S3 Public Access", test_s3_public_access),
        ("S3 Secure Transport", test_s3_secure_transport),
        ("S3 Tags", test_s3_tags),
        ("RDS Backup Retention", test_rds_backup_retention),
        ("RDS Encryption", test_rds_encryption),
        ("RDS Public Access", test_rds_public_access),
        ("RDS Automatic Upgrades", test_rds_auto_minor_version_upgrade),
        ("RDS Deletion Protection", test_rds_deletion_protection),
        ("RDS Tags", test_rds_tags),
        ("EBS Volume Encryption", test_ebs_volume_encryption),
        ("EBS Encryption Default", test_ebs_default_encryption),
        ("EBS Tags", test_ebs_tags),
        ("EC2 Tags", test_ec2_tags),
        ("EC2 Security Group Tags", test_ec2_security_group_tags),
        ("Lambda Tags", test_lambda_tags),
        ("CloudTrail Multi-Region", test_cloudtrail_global_logging),
        ("CloudTrail Log File Validation", test_cloudtrail_log_file_validation),
        ("CloudTrail S3 Bucket Protection", test_cloudtrail_s3_bucket_protection),
        ("CloudTrail Logging Recent Stops", test_cloudtrail_logging_recent_stops),
        ("Web Application Firewall Enabled", test_waf_enabled),
        ("GuardDuty Enabled", test_guardduty_enabled)
    ]

    controls = []
    for control_id, control_fn in control_definitions:
        controls.append(run_control_safely(audit, control_fn, control_id))
    
    # Save controls JSON file.
    with open(f"tmp/controls.json", "w") as f:
        json.dump([c.to_dict() for c in controls], f, indent=4)

    # TODO: Add IAM tests (IAM User Stale Access Keys)
    # TODO: Add S3 object owner check
    # TODO: Add EC2 Public Ports (22, RDS, all ports, etc)
    # TODO: Add WAF Tags
    # TODO: Add GuardDuty findings resolved within a set time period.
    # TODO: Add GuardDuty findings sent to EventBridge every 15 minutes (default is 6 hours).

    return controls

def test_s3_encryption(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="S3 buckets are encrypted at rest.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: S3/buckets.json.",
            "For each S3 bucket, obtained the encryption settings by calling the get_bucket_encryption() boto3 command.",
            "For each S3 bucket, saved the encryption settings: S3/[bucket_name]/encryption.json.",
            "For each S3 bucket, inspected the encryption settings to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["ServerSideEncryptionConfiguration is present in encryption.json."],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )
    if control.is_excluded:
        # No further testing required.
        return control
    
    s3 = audit.session.client("s3")
    # Obtain and save list of buckets.
    buckets = audit.evidence_client.get("S3/buckets.json", lambda: s3.list_buckets())
    # Loop through each bucket
    for bucket in buckets.get("Buckets", []):
        sample = Sample(
            sample_id={"bucket_name": bucket['Name']},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            # Move to next sample, if excluded.
            continue        

        # Obtain and save bucket's encryption settings.
        enc = audit.evidence_client.get_aws(f"S3/buckets/{bucket['Name']}/encryption.json",
            lambda: s3.get_bucket_encryption(Bucket=bucket['Name']),
            not_found_codes=["ServerSideEncryptionConfigurationNotFoundError"]
        )
        if enc.get("ServerSideEncryptionConfiguration"):
            sample.result = True
        else:
            sample.comments = "No encryption configuration found"
        control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} S3 bucket(s) are not encrypted."
    return control

def test_s3_public_access(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="S3 buckets are configured to block public access.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: S3/buckets.json.",
            "For each bucket, obtained the public access block settings by calling the get_public_access_block() boto3 command.",
            "For each bucket, saved the public access block settings: S3/[bucket_name]/public_access_block.json.",
            "For each bucket, inspected the public access block settings to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets are set to true."],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    s3 = audit.session.client("s3")
    # Obtain and save list of buckets.
    buckets = audit.evidence_client.get("S3/buckets.json", lambda: s3.list_buckets())
    # Evaluate each bucket
    for bucket in buckets.get("Buckets", []):
        sample = Sample(
            sample_id={"bucket_name": bucket["Name"]},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            # Move to next sample, if excluded.
            continue
        
        # Fetch public access block
        public_access_block = audit.evidence_client.get_aws(
            f"S3/buckets/{bucket['Name']}/public_access_block.json",
            lambda: s3.get_public_access_block(Bucket=bucket["Name"]),
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )
        if not public_access_block:
            sample.comments = "No Public Access Block configuration found."
            control.samples.append(sample)
            continue

        config = public_access_block.get("PublicAccessBlockConfiguration", {})
        block_acls = config.get("BlockPublicAcls", False)
        ignore_acls = config.get("IgnorePublicAcls", False)
        block_policy = config.get("BlockPublicPolicy", False)
        restrict_buckets = config.get("RestrictPublicBuckets", False)

        # Determine result
        is_blocking_public_access = all([block_acls, ignore_acls, block_policy, restrict_buckets])
        if is_blocking_public_access:
            sample.result = True
        else:
            sample.comments = "One or more public access settings are disabled"
        control.samples.append(sample)


    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} S3 buckets are not blocking public access."
    return control

"""
    Control: S3 buckets must have required tags applied with non-empty values.
"""
# TODO: Update logic for opt-in regions
def test_s3_tags(audit, control_id, risk_rating=1):
    # Get base required tags.
    control_config = audit.config.get("control_config") or {}
    base_required_tags = control_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Check if 's3_required_tags' is set. If so, override base required tags.
    control_config = audit.config.get("control_config") or {}
    s3_required_tags = control_config.get("s3_required_tags")
    if s3_required_tags:
        required_tags = s3_required_tags
    else:
        required_tags = base_required_tags

    control = Control(
        control_id=control_id,
        control_description=(
            "S3 buckets must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: S3/buckets.json.",
            "For each bucket, obtained its tags by calling the get_bucket_tagging() boto3 command.",
            "For each bucket, saved the tags: S3/[bucket_name]/tags.json.",
            f"For each bucket, inspected the tags to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    s3 = audit.session.client("s3")
    buckets = audit.evidence_client.get("S3/buckets.json", lambda: s3.list_buckets())

    for bucket in buckets.get("Buckets", []):
        sample = Sample(
            sample_id={"bucket_name": bucket["Name"]},
            control_id=control_id
        )
        if process_sample_exclusion(control, sample, audit):
            continue

        # Fetch bucket tags
        tags_response = audit.evidence_client.get_aws(
            f"S3/buckets/{bucket['Name']}/tags.json",
            lambda: s3.get_bucket_tagging(Bucket=bucket["Name"]),
            not_found_codes=["NoSuchTagSet"]
        )
        if not tags_response:
            sample.comments = "Tags not found on this bucket."
            control.samples.append(sample)
            continue

        actual_bucket_tags = {t["Key"]: t.get("Value", "") for t in tags_response.get("TagSet", [])}
        evaluate_tags(sample, required_tags, actual_bucket_tags)
        control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} bucket(s) missing required tags or have empty values."
        )

    return control

def test_s3_secure_transport(audit, control_id, risk_rating=0):
    control = Control(
        control_id=control_id,
        control_description= "S3 buckets are configured to encrypt data in-transit.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of buckets: S3/buckets.json.",
            "For each bucket, obtained the bucket policy by calling the get_bucket_policy() boto3 command.",
            "For each bucket, saved the bucket policy: S3/buckets/[bucket_name]/bucket_policy.json.",
            "For each bucket, inspected the bucket policy to determine if a statement exists that denies requests when aws:SecureTransport is false."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    s3 = audit.session.client("s3")

    # Obtain and save list of buckets
    buckets = audit.evidence_client.get(
        "S3/buckets.json",
        lambda: s3.list_buckets()
    )

    for bucket in buckets.get("Buckets", []):
        bucket_name = bucket["Name"]
        sample = Sample(
            sample_id={"bucket_name": bucket_name},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        # Fetch bucket policy
        policy = audit.evidence_client.get_aws(
            f"S3/buckets/{bucket_name}/bucket_policy.json",
            lambda: s3.get_bucket_policy(Bucket=bucket_name),
            not_found_codes=["NoSuchBucketPolicy"]
        )

        if not policy:
            sample.comments = "No bucket policy found."
            control.samples.append(sample)
            continue

        try:
            policy_doc = json.loads(policy.get("Policy", "{}"))
        except Exception:
            sample.comments = "Unable to parse bucket policy."
            control.samples.append(sample)
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
            sample.result = True
        else:
            sample.comments = "No bucket policy statement enforcing SecureTransport."

        control.samples.append(sample)

    control.evaluate_samples()

    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} S3 bucket(s) do not enforce secure transport (HTTPS)."
        )

    return control

def test_iam_password_policy(audit, control_id, risk_rating=2):
    # Retrieve values from config. If not available, set safe defaults.
    control_config = audit.config.get("control_config") or {}
    required_min_length = control_config.get("iam_password_min_length", 14)
    req_min_complexity_types = control_config.get("iam_password_min_complexity_types", 4)
    required_password_history = control_config.get("iam_password_password_history", 24)

    control = Control(
        control_id=control_id,
        control_description=(
            f"IAM passwords must comply with the organizations password complexity requirements."
        ),      
        test_procedures=[
            "Obtained the IAM password configuration by calling the get_account_password_policy() boto3 command.",
            "Saved the AWS password policy: IAM/password_policy.json.",
            "Inspected the password configuration to determine if they comply with the test attribute(s) defined below."
        ],
        test_attributes=[
            f"MinimumPasswordLength must be >= {required_min_length}.",
            f"At least {req_min_complexity_types} complexity types (RequireSymbols, RequireNumbers, "
            "RequireUppercaseCharacters, and RequireLowercaseCharacters) are set to True.",
            f"PasswordReusePrevention must be >= {required_password_history}."
        ],
        audit=audit,
        risk_rating=risk_rating
    )

    # Gather evidence
    iam = audit.session.client("iam")
    policy = audit.evidence_client.get_aws(
        "IAM/password_policy.json",
        lambda: iam.get_account_password_policy(),
        not_found_codes=["NoSuchEntity"]
    )
    if not policy:
        control.result = False
        control.result_description = "Exceptions Noted. No password policy configured."
        return control

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
    required_expiration = control_config.get("iam_password_require_expiration", False)
    if required_expiration:
        required_max_password_age = control_config.get("iam_password_max_password_age", 365)        
        expire_enabled = password_policy.get("ExpirePasswords", False)
        actual_max_password_age = password_policy.get("MaxPasswordAge")
        # Add password expiration as test attribute.
        control.test_attributes.append(
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

    # --- Final result ---
    control.result = len(failures) == 0
    if not control.result:
        control.result_description = "; ".join(failures)
        control.result_description = "Exceptions Noted. " + control.result_description
    return control

def test_root_no_access_keys(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="Root account does not have any active access keys.",      
        test_procedures=[
            "Obtained the AWS account summary by calling the get_account_summary() boto3 command.",
            "Saved the account summary in the audit evidence folder (IAM/account_summary.json)",
            "Inspected the account summary to determine if 'AccountAccessKeysPresent' is set to 0."
        ],
        test_attributes=[],
        audit=audit,
        risk_rating = risk_rating
    )

    if control.is_excluded:
        return control

    iam = audit.session.client("iam")
    summary = audit.evidence_client.get_aws(
        "IAM/account_summary.json",
        lambda: iam.get_account_summary()
    )

    account_summary = summary.get("SummaryMap", {})
    root_keys = account_summary.get("AccountAccessKeysPresent", 0)

    if root_keys == 0:
        control.result = True
    else:
        control.result = False
        control.result_description = f"Exceptions Noted. Root account has {root_keys} access key(s)"

    return control

def test_root_mfa_enabled(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="Root account has MFA enabled.",
        test_procedures=[
            "Obtained the AWS account summary by calling the get_account_summary() boto3 command.",
            "Saved the account summary: IAM/account_summary.json",
            "Inspected the account summary to determine if 'AccountMFAEnabled' is set to 1."
        ],
        test_attributes=[],
        audit=audit,
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    iam = audit.session.client("iam")
    summary = audit.evidence_client.get_aws(
        "IAM/account_summary.json",
        lambda: iam.get_account_summary()
    )

    account_summary = summary.get("SummaryMap", {})
    mfa_enabled = account_summary.get("AccountMFAEnabled", 0)

    if mfa_enabled == 1:
        control.result = True
    else:
        control.result = False
        control.result_description = "Exceptions Noted. Root account does not have MFA enabled."
        
    return control

def test_iam_users_mfa(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="IAM users with an active console password have MFA enabled.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of IAM users: IAM/users.json.",
            "For each IAM user, obtained the login profile information by calling the get_login_profile() boto3 command.",
            "For each IAM user, saved the login profile: IAM/users/[user_name]/login_profile.json.",
            "Saved the login profile for each user in the audit evidence folder (IAM/users/[user_name]/login_profile.json).",
            "For each IAM user with a login profile, obtained the MFA device information by calling the list_mfa_devices() boto3 command.",
            "For each IAM user with a login profile, saved the MFA device information: IAM/users/[user_name]/mfa_devices.json]",
            "For each IAM user with a login profile, inspected mfa_devices.json to determine if at least one MFA device is registered."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["IAM User Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    iam = audit.session.client("iam")
    users = audit.evidence_client.get_aws(
        "IAM/users.json",
        lambda: iam.list_users()
    ).get("Users", [])

    for user in users:
        username = user["UserName"]
        sample = Sample(
            sample_id={"user": username},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        # Check if user has a console password
        try:
            login_profile = audit.evidence_client.get_aws(
                f"IAM/users/{username}/login_profile.json",
                lambda: iam.get_login_profile(UserName=username),
                not_found_codes=["NoSuchEntity"]
            )
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                sample.is_excluded = True
                sample.comments = "User has no console password (programmatic access only)."
                control.samples.append(sample)
                continue
            else:
                raise

        # Check if login profile in null.
        login_profile = login_profile or {}
        if not login_profile.get("LoginProfile"):
            sample.result = True
            sample.comments = "User has no console password (programmatic access only)."
            control.samples.append(sample)
            continue

        # Check MFA devices
        mfa_devices = audit.evidence_client.get_aws(
            f"IAM/users/{username}/mfa_devices.json",
            lambda: iam.list_mfa_devices(UserName=username)
        ).get("MFADevices", [])

        if mfa_devices:
            sample.result = True
        else:
            sample.comments = "No MFA device enabled for this user."

        control.samples.append(sample)

    control.evaluate_samples()

    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} IAM user(s) do not have MFA enabled."
        )

    return control

def test_iam_access_key_age(audit, control_id, risk_rating=3):
    control_config = audit.config.get("control_config") or {}
    max_age_days = control_config.get("iam_key_max_age", 90)

    control = Control(
        control_id=control_id,
        control_description=f"IAM access keys are rotated at least every {max_age_days} days.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of IAM users: IAM/users.json.",
            "For each IAM user, obtained access key metadata by calling the list_access_keys() boto3 command.",
            "For each IAM user, saved access key metadata: IAM/users/[user_name]/access_keys.json",
            "Inspected the 'AccessKeyMetadata' for each user to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=[
            f"'CREATE_DATE <= {max_age_days} days ago (for keys with an 'ACTIVE' status)."
        ],
        audit=audit,
        table_headers=["User", "Access Key ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    iam = audit.session.client("iam")
    users = audit.evidence_client.get_aws(
        "IAM/users.json",
        lambda: iam.list_users()
    )

    now = datetime.now(timezone.utc)

    for user in users.get("Users", []):
        username = user["UserName"]

        keys = audit.evidence_client.get_aws(
            f"IAM/users/{username}/access_keys.json",
            lambda: iam.list_access_keys(UserName=username)
        )

        for key in keys.get("AccessKeyMetadata", []):
            sample = Sample(
                sample_id={
                    "user": username,
                    "access_key_id": key["AccessKeyId"]
                },
                control_id=control_id
            )
            if key["Status"] != "Active":
                sample.is_excluded = True
                sample.comments = "N/A - key is inactive."
                control.samples.append(sample)
                continue

            if process_sample_exclusion(control, sample, audit):
                continue

            create_date = key["CreateDate"]

            if isinstance(create_date, str):
                create_date = create_date.replace("Z", "+00:00")
                create_date = datetime.fromisoformat(create_date)

            actual_age_days = (now - create_date).days

            if actual_age_days <= max_age_days:
                sample.result = True
            else:
                sample.comments = f"Key is {actual_age_days} days old."

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} IAM key(s) are over {max_age_days} days old."
    return control

"""
    NOTE: Used by region based tests (EC2, RDS, SNS, GuardDuty, etc)
    Return in-scope AWS regions based on config.json. If not set, return result from describe_regions.
    Raises:
        ValueError: If config contains invalid regions.
"""
def get_regions(audit):
    ec2 = audit.session.client("ec2")
    regions = audit.evidence_client.get_aws(
        "EC2/regions.json",
        lambda: ec2.describe_regions(
            AllRegions=True,
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"]}
            ]
        )
    )
    available_regions = {r["RegionName"] for r in regions["Regions"]}

    # Pull from config and lower-case region values
    control_config = audit.config.get("control_config") or {}
    config_regions = control_config.get("in_scope_regions", [])
    config_regions = [r.lower() for r in config_regions]

    if not config_regions:
        # in_scope_regions not set in config value. Return all available regions.
        return sorted(available_regions)

    # Check for invalid regions
    config_regions_set = set(config_regions)
    invalid_regions = config_regions_set - available_regions
    if invalid_regions:
        raise ValueError(
            f"Invalid regions in config: {sorted(invalid_regions)}. "
            f"Valid regions are: {sorted(available_regions)}"
        )

    # Return validated regions
    return [r for r in config_regions if r in available_regions]


def test_rds_encryption(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="RDS instances are encrypted at rest.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: RDS/region_name/db_instances.json.",
            "For each RDS instance, inspected the `StorageEncrypted` setting to determine if it was set to `true`."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
                f"RDS/{region}/db_instances.json",
                fetch_fn=None,  # fetch_fn is not used when using paginator_params
                paginator_params={
                    "client": rds,
                    "method_name": "describe_db_instances",
                    "pagination_key": "DBInstances"
                }
            )

        for db in instances.get("DBInstances", []):
            sample = Sample(
                sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            if db.get("StorageEncrypted"):
                sample.result = True
            else:
                sample.comments = "RDS instance is not encrypted."

            control.samples.append(sample)
    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instance(s) are not encrypted."
    return control

def test_rds_public_access(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="RDS instances are not publicly accessible.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: RDS/[region_name]/db_instances.json)",
            "For each RDS instance, inspected the 'PubliclyAccessible' setting to determine if it was set to 'false'."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"RDS/{region}/db_instances.json",
            lambda: rds.describe_db_instances()
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(
                sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            if not db.get("PubliclyAccessible", False):
                sample.result = True
            else:
                sample.comments = "Instance is publicly accessible."

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instance(s) are publicly accessible."
    return control

"""
    Control: RDS instances must have required tags applied with non-empty values.
"""
def test_rds_tags(audit, control_id, risk_rating=1):
    # Get base required tags.
    control_config = audit.config.get("control_config") or {}
    base_required_tags = control_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'rds_required_tags' is set
    required_tags = control_config.get("rds_required_tags", base_required_tags)

    control = Control(
        control_id=control_id,
        control_description=(
            "RDS instances must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: RDS/[region_name]/db_instances.json).",
            f"For each RDS instance, reviewed the `TagList` to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"RDS/{region}/db_instances.json",
            fetch_fn=None,
            paginator_params={
                "client": rds,
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(
                sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            actual_db_tags = {t["Key"]: t.get("Value", "") for t in db.get("TagList", [])}
            evaluate_tags(sample, required_tags, actual_db_tags)
            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} RDS instance(s) are missing required tags or have empty values."
        )

    return control

def test_rds_backup_retention(audit, control_id, risk_rating=1):
    control_config = audit.config.get("control_config") or {}
    required_rds_retention_days = control_config.get("rds_backup_retention_days", 14)
    control = Control(
        control_id=control_id,
        control_description=f"RDS backups are retained for at least {required_rds_retention_days} days.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: RDS/[region_name]/db_instances.json.",
            f"For each RDS instance, inspected the `BackupRetentionPeriod` to determine if it is greater than or equal to {required_rds_retention_days} days."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"RDS/{region}/db_instances.json",
            lambda: rds.describe_db_instances()
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(
                sample_id={"region": region, "db_instance": db["DBInstanceIdentifier"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            actual_retention_days = db.get("BackupRetentionPeriod", 0)

            if actual_retention_days >= required_rds_retention_days:
                sample.result = True
            else:
                sample.comments = f"Retention is {actual_retention_days} days"

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instance(s) do not retain backups for at least {required_rds_retention_days} days."
    return control

def test_rds_auto_minor_version_upgrade(audit, control_id, risk_rating=1):
    control = Control(
        control_id=control_id,
        control_description="RDS instances have automatic minor version upgrades enabled.",
        test_procedures=[
            "For each in-scope region, obtained a list of DB instances by calling the describe_db_instances() boto3 command.",
            "For each in-scope region, saved the list of RDS instances: RDS/[region_name]/db_instances.json.",
            "For each RDS instance, inspected the 'AutoMinorVersionUpgrade' setting to determine if it was set to 'true'."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"RDS/{region}/db_instances.json",
            fetch_fn=None,
            paginator_params={
                "client": rds,
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        for db in instances.get("DBInstances", []):
            sample = Sample(
                sample_id={
                    "region": region,
                    "db_instance": db["DBInstanceIdentifier"]
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            if db.get("AutoMinorVersionUpgrade"):
                sample.result = True
            else:
                sample.comments = "Automatic minor version upgrades are not enabled."

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} RDS instance(s) do not have automatic minor version upgrades enabled."
        )

    return control

def test_rds_deletion_protection(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="RDS instances have deletion protection enabled at the cluster or instance level.",
        test_procedures=[
            "For each in-scope region, obtained a list of RDS instances and RDS clusters using describe_db_instances() and describe_db_clusters() boto3 commands.",
            "Saved the list of RDS instances: RDS/[region_name]/db_instances.json and DB clusters: RDS/[region_name]/db_clusters.json.",
            "Inspected each RDS instance to determine if 'DeletionProtection' was set to 'true' at the instance or cluster level."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = audit.session.client("rds", region_name=region)

        # Get DB instances
        instances = audit.evidence_client.get_aws(
            f"RDS/{region}/db_instances.json",
            fetch_fn=None,
            paginator_params={
                "client": rds,
                "method_name": "describe_db_instances",
                "pagination_key": "DBInstances"
            }
        )

        # Get DB clusters
        clusters = audit.evidence_client.get_aws(
            f"RDS/{region}/db_clusters.json",
            fetch_fn=None,
            paginator_params={
                "client": rds,
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
            sample = Sample(
                sample_id={
                    "region": region,
                    "db_instance": db["DBInstanceIdentifier"]
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
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
                sample.result = True
            else:
                if cluster_id:
                    sample.comments = "Deletion protection is not enabled at either the instance or cluster level."
                else:
                    sample.comments = "Deletion protection is not enabled at the instance level."
            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} RDS instance(s) do not have deletion protection enabled."
        )

    return control

def test_ec2_security_group_tags(audit, control_id, risk_rating=1):
    # Get required tags.
    control_config = audit.config.get("control_config") or {}
    required_tags = control_config.get("ec2_sg_required_tags", ["Owner", "Description", "ReviewedBy", "LastReviewedDate"])

    control = Control(
        control_id=control_id,
        control_description=(
            "EC2 security groups have required tags applied and tag values are not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained a list of EC2 security groups by calling describe_security_groups() boto3 command.",
            "For each in-scope region, saved the list of security groups: EC2/[region]/security_groups.json",
            f"Inspected each security group's 'Tags' attribute to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Security Group ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        security_groups = audit.evidence_client.get_aws(
            f"EC2/{region}/security_groups.json",
            fetch_fn=None,
            paginator_params={
                "client": ec2,
                "method_name": "describe_security_groups",
                "pagination_key": "SecurityGroups"
            }
        )

        for sg in security_groups.get("SecurityGroups", []):
            sample = Sample(
                sample_id={
                    "region": region,
                    "security_group_id": sg["GroupId"]
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            # Security group tags
            actual_sg_tags = {
                t["Key"]: t.get("Value", "")
                for t in sg.get("Tags", [])
            }

            evaluate_tags(sample, required_tags, actual_sg_tags)
            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} security group(s) are missing required tags or have empty values."
        )

    return control

def test_ec2_tags(audit, control_id, risk_rating=1):
    # Get base required tags.
    control_config = audit.config.get("control_config") or {}
    base_required_tags = control_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'ec2_required_tags' is set
    required_tags = control_config.get("ec2_required_tags", base_required_tags)

    control = Control(
        control_id=control_id,
        control_description=(
            "EC2 instances must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of EC2 instances by calling describe_instances() boto3 command.",
            "For each in-scope AWS region, saved the list of EC2 instances: EC2/[region_name]/instances.json",
            f"For each EC2 instance, reviewed the 'Tags' to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Instance ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        instances = audit.evidence_client.get_aws(
            f"EC2/{region}/instances.json",
            fetch_fn=None,
            paginator_params={
                "client": ec2,
                "method_name": "describe_instances",
                "pagination_key": "Reservations"
            }
        )

        for reservation in instances.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                sample = Sample(
                    sample_id={
                        "region": region,
                        "instance_id": instance["InstanceId"]
                    },
                    control_id=control_id
                )

                if process_sample_exclusion(control, sample, audit):
                    continue

                # EC2 tags come in the 'Tags' attribute
                instance_tags = {
                    t["Key"]: t.get("Value", "")
                    for t in instance.get("Tags", [])
                }

                evaluate_tags(sample, required_tags, instance_tags)
                control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} EC2 instance(s) are missing required tags or have empty values."
        )

    return control

def test_ebs_volume_encryption(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="EBS volumes are encrypted at rest.",
        test_procedures=[
            "For each in-scope region, obtained a list of EBS volumes by calling describe_volumes() boto3 command.",
            "For each in-scope region, saved the list of EBS volumes: EC2/[region_name]/volumes.json.",
            "For each EBS volume, inspected the 'Encrypted' attribute to determine it is set to 'true'."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Volume ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        volumes = audit.evidence_client.get_aws(
            f"EC2/{region}/volumes.json",
            fetch_fn=None,
            paginator_params={
                "client": ec2,
                "method_name": "describe_volumes",
                "pagination_key": "Volumes"
            }
        )

        for volume in volumes.get("Volumes", []):
            sample = Sample(
                sample_id={"region": region, "volume_id": volume["VolumeId"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            if volume.get("Encrypted"):
                sample.result = True
            else:
                sample.comments = "EBS volume is not encrypted."

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} EBS volume(s) are not encrypted."
        )

    return control

def test_ebs_tags(audit, control_id, risk_rating=1):
    """
    Control: EBS volumes must have required tags applied with non-empty values.
    """
    # Get base required tags.
    control_config = audit.config.get("control_config") or {}
    base_required_tags = control_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'ebs_required_tags' is set
    required_tags = control_config.get("ebs_required_tags", base_required_tags)

    control = Control(
        control_id=control_id,
        control_description=(
            "EBS volumes must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of EBS volumes by calling describe_volumes() boto3 command.",
            "Saved the list of volumes in the audit evidence folder (EC2/[region_name]/volumes.json).",
            "For each volume, obtained its tags from the 'Tags' attribute.",
            f"Inspected each EBS volume to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Volume ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        volumes = audit.evidence_client.get_aws(
            f"EC2/{region}/volumes.json",
            fetch_fn=None,
            paginator_params={
                "client": ec2,
                "method_name": "describe_volumes",
                "pagination_key": "Volumes"
            }
        )

        for volume in volumes.get("Volumes", []):
            sample = Sample(
                sample_id={"region": region, "volume_id": volume["VolumeId"]},
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            # EBS tags come in the 'Tags' attribute
            volume_tags = {t["Key"]: t.get("Value", "") for t in volume.get("Tags", [])}

            # Reuse helper to evaluate tags
            evaluate_tags(sample, required_tags, volume_tags)

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} EBS volume(s) are missing required tags or have empty values."
        )

    return control

def test_ebs_default_encryption(audit, control_id, risk_rating=0):
    # NOTE: Risk rating is set to 'Informational'. Not having this set does not mean there are unencrypted EBS volumes.
    control = Control(
        control_id=control_id,
        control_description="EBS volumes must have default encryption enabled in each region.",
        test_procedures=[
            "For each in-scope region, obtained the EBS default encryption settings by calling get_ebs_encryption_by_default() boto3 command.",
            "For each in-scope region, saved the EBS default encryption settings: EC2/[region_name]/default_ebs_encryption.json.",
            "Inspected the configuration for each region to determine if 'EbsEncryptionByDefault' is set to True."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = audit.session.client("ec2", region_name=region)

        default_encryption = audit.evidence_client.get_aws(
            f"EC2/{region}/default_ebs_encryption.json",
            lambda: ec2.get_ebs_encryption_by_default()
        )

        sample = Sample(
            sample_id={"region": region},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        if default_encryption.get("EbsEncryptionByDefault"):
            sample.result = True
        else:
            sample.comments = "EBS default encryption is not enabled in this region."

        control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} region(s) do not have EBS default encryption enabled."
        )

    return control

def test_lambda_tags(audit, control_id, risk_rating=1):
    # Get base required tags.
    control_config = audit.config.get("control_config") or {}
    base_required_tags = control_config.get("base_required_tags", ["Owner", "Description", "Classification"])

    # Override if 'lambda_required_tags' is set
    required_tags = control_config.get("lambda_required_tags", base_required_tags)

    control = Control(
        control_id=control_id,
        control_description=(
            "Lambda functions must have required tags applied and tag values must not be empty."
        ),
        test_procedures=[
            "For each in-scope region, obtained the list of Lambda functions by calling list_functions() boto3 command.",
            "Saved the list of functions in the audit evidence folder (Lambda/[region_name]/functions.json).",
            "For each function, obtained its tags using list_tags() boto3 command.",
            "Saved the tags for each function in the audit evidence folder (Lambda/[region_name]/functions/[function_name]/tags.json).",
            f"Inspected each Lambda function to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Function Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        lambda_client = audit.session.client("lambda", region_name=region)

        functions = audit.evidence_client.get_aws(
            f"Lambda/{region}/functions.json",
            fetch_fn=None,
            paginator_params={
                "client": lambda_client,
                "method_name": "list_functions",
                "pagination_key": "Functions"
            }
        )

        for fn in functions.get("Functions", []):
            sample = Sample(
                sample_id={
                    "region": region,
                    "function_name": fn["FunctionName"]
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue

            # Fetch tags via ARN
            arn = fn.get("FunctionArn")
            tags_response = audit.evidence_client.get_aws(
                f"Lambda/{region}/functions/{fn['FunctionName']}/tags.json",
                lambda: lambda_client.list_tags(Resource=arn)
            )

            lambda_tags = tags_response.get("Tags", {})
            evaluate_tags(sample, required_tags, lambda_tags)
            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} Lambda function(s) are missing required tags or have empty values."
        )

    return control

def test_cloudtrail_global_logging(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="At least one multi-region CloudTrail trail has logging enabled.",
        test_procedures=[
            "Obtained a list of CloudTrail trails by calling the describe_trails() boto3 command.",
            "Saved the list of CloudTrail trails: CloudTrail/trails.json.",
            "For each CloudTrail trail, inspected the trail configuration to determine whether 'IsMultiRegionTrail' is set to 'true'.",
            "For each multi-region trail, obtained the trail status by calling the get_trail_status() boto3 command.",
            "For each multi-region trail, saved the trail status: CloudTrail/trails/[trail_name]/trail_status.json.",
            "Inspected the trail configuration and status to determine if at least one trail complies with the test attribute(s) defined below."
        ],
        test_attributes=[
            "At least one trail must have IsMultiRegionTrail = true and IsLogging = true."
        ],
        audit=audit,
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        control.result = False
        control.result_description = "Exceptions Noted. No CloudTrail trail was found."
        return control

    found_valid_trail = False
    for trail in trails:
        if not trail.get("IsMultiRegionTrail", False):
            continue
        status = audit.evidence_client.get_aws(
            f"CloudTrail/trails/{trail['Name']}/trail_status.json",
            lambda: ct.get_trail_status(Name=trail["TrailARN"])
        )
        if status.get("IsLogging", False):
            found_valid_trail = True
            break

    if found_valid_trail:
        control.result = True
    else:
        control.result = False
        control.result_description = (
            "Exceptions Noted. No multi-region CloudTrail trail with active logging was found."
        )

    return control

def test_cloudtrail_log_file_validation(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="CloudTrail trails have log file validation enabled.",
        test_procedures=[
            "Obtained CloudTrail trails using the describe_trails() boto3 command.",
            "Saved the trail configuration in the audit evidence folder (CloudTrail/trails.json).",
            "Inspected each trail's configuration to determine if 'LogFileValidationEnabled' was set to True for all trails."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Trail Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        control.result = False
        control.result_description = "Exceptions Noted. No CloudTrail trails are configured."
        return control

    for trail in trails:
        trail_name = trail["Name"]
        sample = Sample(
            sample_id={"trail_name": trail_name},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        log_validation = trail.get("LogFileValidationEnabled", False)
        if log_validation:
            sample.result = True
        else:
            sample.comments = "Log file validation is disabled."
        control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} trail(s) do not have log file validation enabled."
        )

    return control

def test_cloudtrail_s3_bucket_protection(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="CloudTrail S3 buckets are configured to block public access.",
        test_procedures=[
            "Obtained a list of CloudTrails by calling the describe_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (CloudTrail/trails.json).",
            "For each trail, obtained the S3 bucket name and checked the bucket's public access block settings using get_public_access_block() boto3 command.",
            "Saved the public access block settings for each bucket in the audit evidence folder (S3/buckets/[bucket_name]/public_access_block.json).",
            "Inspected the public access block settings for each S3 bucket containing CloudTrail logs to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=[
            "CloudTrail S3 buckets must block public access (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets = True)."
        ],
        audit=audit,
        table_headers=["Trail Name", "Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails()
    ).get("trailList", [])

    for trail in trails:
        trail_name = trail.get("Name")
        bucket_name = trail.get("S3BucketName")

        sample = Sample(
            sample_id={"trail_name": trail_name, "bucket_name": bucket_name},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        if not bucket_name:
            sample.comments = "Trail does not have an associated S3 bucket."
            control.samples.append(sample)
            continue

        # Fetch public access block
        public_access_block = audit.evidence_client.get_aws(
            f"S3/buckets/{bucket_name}/public_access_block.json",
            lambda: audit.session.client("s3").get_public_access_block(Bucket=bucket_name),
            not_found_codes=["NoSuchPublicAccessBlockConfiguration"]
        )

        if not public_access_block:
            sample.comments = "No Public Access Block configuration found."
            control.samples.append(sample)
            continue

        config = public_access_block.get("PublicAccessBlockConfiguration", {})
        block_acls = config.get("BlockPublicAcls", False)
        ignore_acls = config.get("IgnorePublicAcls", False)
        block_policy = config.get("BlockPublicPolicy", False)
        restrict_buckets = config.get("RestrictPublicBuckets", False)

        # Determine result
        if all([block_acls, ignore_acls, block_policy, restrict_buckets]):
            sample.result = True
        else:
            sample.comments = "One or more public access settings are not enabled."

        control.samples.append(sample)

    control.evaluate_samples()

    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} CloudTrail bucket(s) are not blocking public access."
        )

    return control

"""
    Ensure CloudTrail logging has not been stopped within the configured lookback period.
"""
def test_cloudtrail_logging_recent_stops(audit, control_id, risk_rating=3):
    control_config = audit.config.get("control_config") or {}
    lookback_days = control_config.get("cloudtrail_logging_lookback_days", 365)

    control = Control(
        control_id=control_id,
        control_description=(
            f"CloudTrail logging has not been stopped in the last {lookback_days} days."
        ),
        test_procedures=[
            "Obtained a list of CloudTrails by calling the describe_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (CloudTrail/trails.json).",
            "For each trail, called get_trail_status() to check IsLogging and StopLoggingTime.",
            f"Saved each trail's status in the audit evidence folder (CloudTrail/trails/[trail_name]/trail_status.json).",
            f"Inspected the 'TimeLoggingStopped' variable to determine if logging has been stopped in the last {lookback_days} days."
        ],
        test_attributes=[
            f"'TimeLoggingStopped' must be empty OR is more than {lookback_days} days ago."
        ],
        audit=audit,
        table_headers=["Trail Name", "Is Logging", "Last Stop Time", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = audit.session.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails()
    ).get("trailList", [])

    now = datetime.now(timezone.utc)
    lookback_threshold = now - timedelta(days=lookback_days)

    for trail in trails:
        trail_name = trail.get("Name")
        sample = Sample(
            sample_id={"trail_name": trail_name},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        status = audit.evidence_client.get_aws(
            f"CloudTrail/trails/{trail_name}/trail_status.json",
            lambda: ct.get_trail_status(Name=trail_name)
        )

        is_logging = status.get("IsLogging", False)
        stop_time = status.get("StopLoggingTime")

        # Convert StopLoggingTime to datetime if present
        if stop_time:
            if isinstance(stop_time, str):
                stop_time = datetime.fromisoformat(stop_time.replace("Z", "+00:00"))

        # Determine result
        if not is_logging:
            sample.result = False
            sample.comments = "CloudTrail logging is currently stopped."
        elif stop_time and stop_time >= lookback_threshold:
            sample.result = False
            sample.comments = f"Logging was stopped recently on {stop_time.isoformat()}."
        else:
            sample.result = True

        control.samples.append(sample)

    control.evaluate_samples()

    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} trail(s) are not currently logging or have been stopped "
            f"within the last {lookback_days} days."
        )

    return control

def test_waf_enabled(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="WAF is enabled on Application Load Balancers and API Gateways.",
        test_procedures=[
            "For each in-scope region, obtained a list of Web ACLs by calling list_web_acls() boto3 command.",
            "Saved the list of Web ACLs (WAF/[region]/web_acls.json).",
            "For each Web ACL, obtained a list of associated resources by calling the list_resources_for_web_acl() boto3 command.",
            "By default the list_resources_for_web_acl() only provide a list of Application Load Balancers.",
            "Saved the Application Load Balancers associated with the ACL (WAF/[region]/[web_acl_name]/resources.json).",
            "Re-ran the list_resources_for_web_acl() boto3 command to get the associated API Gateways.",     
            "For each in-scope region, obtained a list of Application Load Balancers using describe_load_balancers() boto3 command.",
            "Saved the list of load balancers in the audit evidence folder (ELBv2/[region_name]/load_balancers.json).",
            "For each load balancer, checked if Load Balancer ARN was associated with a Web ACL.",
            "For each in-scope region, obtained a list of API Gateways using get_rest_apis() boto3 command.",
            "Saved the list of API Gateways in the audit evidence folder (APIGateway/[region_name]/rest_apis.json).",
            "For each API gateway to check if it was associated with a Web ACL."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Resource Type", "Resource ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        waf = audit.session.client("wafv2", region_name=region)
        elbv2 = audit.session.client("elbv2", region_name=region)
        apigw = audit.session.client("apigateway", region_name=region)

        # Get list of Web ACLs (REGIONAL scope for ALB + API Gateway)
        web_acls = audit.evidence_client.get_aws(
            f"WAF/{region}/web_acls.json",
            lambda: waf.list_web_acls(Scope="REGIONAL")
        )

        # Preload WAF information
        acl_to_alb_resources = {}
        acl_to_api_resources = {}

        for acl in web_acls.get("WebACLs", []):
            web_acl_arn = acl["ARN"]
            # ALBs
            alb_resources = audit.evidence_client.get_aws(
                f"WAF/{region}/{acl['Name']}/resources_alb.json",
                lambda: waf.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceType="APPLICATION_LOAD_BALANCER"
                )
            )
            acl_to_alb_resources[web_acl_arn] = set(alb_resources.get("ResourceArns", []))

            # API Gateway
            api_resources = audit.evidence_client.get_aws(
                f"WAF/{region}/{acl['Name']}/resources_apigw.json",
                lambda: waf.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceType="API_GATEWAY"
                )
            )
            acl_to_api_resources[web_acl_arn] = set(api_resources.get("ResourceArns", []))        

        # ALBs
        lbs = audit.evidence_client.get_aws(
            f"ELBv2/{region}/load_balancers.json",
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
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
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
                sample.result = True
            else:
                sample.comments = "No WAF Web ACL associated."

            control.samples.append(sample)

        # API Gateway (REST APIs)
        apis = audit.evidence_client.get_aws(
            f"APIGateway/{region}/rest_apis.json",
            lambda: apigw.get_rest_apis()
        )

        for api in apis.get("items", []):
            sample = Sample(
                sample_id={
                    "region": region,
                    "resource_type": "API Gateway",
                    "resource_id": api["id"]
                },
                control_id=control_id
            )

            if process_sample_exclusion(control, sample, audit):
                continue
            
            api_gw_arn = f"arn:aws:apigateway:{region}::/restapis/{api['id']}"
            api_gw_attached = any(
                any(r.startswith(api_gw_arn) for r in resource_set)
                for resource_set in acl_to_api_resources.values()
            )

            if api_gw_attached:
                sample.result = True
            else:
                sample.comments = "No WAF Web ACL associated."

            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} resource(s) do not have WAF enabled."
        )

    return control

def test_guardduty_enabled(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="GuardDuty is enabled for all in-scope regions.",
        test_procedures=[
            "For each in-scope region, obtained a list of GuardDuty detectors by calling the list_detectors() boto3 command.",
            "For each in-scope region, saved the list of detector IDs: GuardDuty/[region]/detectors.json.",
            "For each detector ID, obtained detector configuration by calling the get_detector() boto3 command.",
            "For each detector ID, saved the detector configuration: GuardDuty/[region]/[detector_id]/config.json.",
            "For each detector ID, inspected the detector configuration to determine whether 'Status' is set to 'ENABLED'."
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        gd = audit.session.client("guardduty", region_name=region)

        sample = Sample(
            sample_id={"region": region},
            control_id=control_id
        )

        if process_sample_exclusion(control, sample, audit):
            continue

        detectors = audit.evidence_client.get_aws(
            f"GuardDuty/{region}/detectors.json",
            lambda: gd.list_detectors()
        ).get("DetectorIds", [])

        if not detectors:
            sample.result = False
            sample.comments = "No GuardDuty detectors in region."
            control.samples.append(sample)
            continue

        enabled_detector_found = False

        for detector_id in detectors:
            config = audit.evidence_client.get_aws(
                f"GuardDuty/{region}/{detector_id}/config.json",
                lambda: gd.get_detector(DetectorId=detector_id)
            )

            if config.get("Status") == "ENABLED":
                enabled_detector_found = True
                break

        if enabled_detector_found:
            sample.result = True
        else:
            sample.result = False
            sample.comments = "Detector(s) found but none are enabled."

        control.samples.append(sample)

    control.evaluate_samples()

    if not control.result:
        control.result_description = (
            f"Exceptions Noted. GuardDuty is not enabled for {control.num_findings} in-scope region(s)."
        )

    return control
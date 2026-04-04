from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from utils import is_control_excluded, process_sample_exclusion, evaluate_tags
import boto3
import botocore
from datetime import datetime, timezone, timedelta

# NOTE: Result is set to "False" until logic determines sample meets testing criteria.
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

def get_aws_account_id():
    client = boto3.client("sts")
    response = client.get_caller_identity()
    aws_account_id = response["Account"]
    return aws_account_id

def test_s3_encryption(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="S3 buckets are encrypted at rest.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of S3 buckets in the audit evidence folder (S3/buckets.json).",
            "Obtained the encryption settings for each bucket by calling the get_bucket_encryption() boto3 command.",
            "Saved the encryption settings for each S3 bucket (S3/[bucket_name]/encryption.json).",
            "Inspected the encryption settings for each bucket to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["ServerSideEncryptionConfiguration is present in encryption.json."],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )
    if control.is_excluded:
        # No further testing required.
        return control
    
    s3 = boto3.client("s3")
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
        control.result_description = f"Exceptions Noted. {control.num_findings} S3 buckets were not encrypted."
    return control

def test_s3_public_access(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="S3 buckets are configured to block public access.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of S3 buckets in the audit evidence folder (S3/buckets.json).",
            "Obtained the public access block settings for each bucket by calling the get_public_access_block() boto3 command.",
            "Saved the public access block settings for each S3 bucket (S3/[bucket_name]/public_access_block.json).",
            "Inspected the public access block settings for each bucket to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets are set to true."],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    s3 = boto3.client("s3")
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
        control.result_description = f"Exceptions Noted. {control.num_findings} S3 buckets were not blocking public access."
    return control

"""
    Control: S3 buckets must have required tags applied with non-empty values.
"""
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
            "Saved the list of S3 buckets in the audit evidence folder (S3/buckets.json).",
            "For each bucket, obtained its tags by calling get_bucket_tagging() boto3 command.",
            "Saved the tags for each bucket in the audit evidence folder (S3/[bucket_name]/tags.json).",
            f"Inspected each bucket to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Bucket Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    s3 = boto3.client("s3")
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

        actual_bucket_tags = {t["Key"]: t.get("Value", "") for t in tags_response.get("TagSet", [])}
        evaluate_tags(sample, required_tags, actual_bucket_tags)
        control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} bucket(s) missing required tags or have empty values."
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
            "Obtained IAM password configuration by using the account_password_policy() boto3 command.",
            "Saved the password configuration in the audit evidence folder (IAM/password_policy.json).",
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
    iam = boto3.client("iam")
    policy = audit.evidence_client.get_aws(
        "IAM/password_policy.json",
        lambda: iam.get_account_password_policy(),
        not_found_codes=["NoSuchEntity"]
    )
    if not policy:
        control.result = False
        control.result_description = "No password policy configured."
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
            "Inspected the account summary to determine if it complies with the test attribute(s) below."
        ],
        test_attributes=[
            "AccountAccessKeysPresent must be 0."
        ],
        audit=audit,
        risk_rating = risk_rating
    )

    if control.is_excluded:
        return control

    iam = boto3.client("iam")
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
            "Saved the account summary in the audit evidence folder (IAM/account_summary.json)",
            "Inspected the account summary to determine if it complies with the test attribute(s) below."
        ],
        test_attributes=[
            "AccountMFAEnabled must be 1."
        ],
        audit=audit,
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    iam = boto3.client("iam")
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
        control.result_description = "Exceptions Noted. Root account does not have MFA enabled"
        
    return control

def test_iam_users_mfa(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="IAM users with an active console password have MFA enabled.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of users in the audit evidence folder (IAM/users.json).",
            "For each user, checked if they have a console login profile using get_login_profile() boto3 command.",
            "Saved the login profile for each user in the audit evidence folder (IAM/users/[user_name]/login_profile.json).",
            "For users with a login profile, obtained MFA devices using list_mfa_devices() boto3 command.",
            "Saved the MFA devices for each user in the audit evidence folder (IAM/users/[user_name]/mfa_devices.json).",
            "Inspected each user's MFA devices to determine if at least one MFA device is enabled."
        ],
        test_attributes=[
            "Each IAM user with console access must have at least one MFA device enabled."
        ],
        audit=audit,
        table_headers=["User Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    iam = boto3.client("iam")
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
            audit.evidence_client.get_aws(
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
            f"Exceptions Noted. {control.num_findings} IAM user(s) with console access do not have MFA enabled."
        )

    return control

def test_iam_access_key_age(audit, control_id, risk_rating=3):
    control_config = audit.config.get("control_config") or {}
    max_age_days = control_config.get("iam_key_max_age", 365)

    control = Control(
        control_id=control_id,
        control_description=f"IAM access keys are rotated at least every {max_age_days} days.",
        test_procedures=[
            "Obtained a list of IAM users by calling the list_users() boto3 command.",
            "Saved the list of IAM users in the audit evidence folder (IAM/users.json).",
            "Obtained the access keys attached to each IAM user by calling the list_access_keys() boto3 command.",
            "Saved the access keys for each user IAM/users/[user_name]/access_keys.json",
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

    iam = boto3.client("iam")
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
        control.result_description = f"Exceptions Noted. {control.num_findings} active IAM keys are older than {max_age_days} days old."
    return control

"""
    NOTE: Used by region based tests (EC2, RDS, SNS, GuardDuty, etc)
    Return in-scope AWS regions based on config.json. If not set, return result from describe_regions.
    Raises:
        ValueError: If config contains invalid regions.
"""
def get_regions(audit):
    ec2 = boto3.client("ec2")
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
            "For each in-scope region, obtained the list of DB instances by calling the describe_db_instances() boto3 command.",
            "Saved the list of DB instances (RDS/[region_name]/db_instances.json).",
            "Inspected the database configuration for each instance(s) to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["StorageEncrypted = True."],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instances are not encrypted."
    return control

def test_rds_public_access(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="RDS instances are not publicly accessible.",
        test_procedures=[
            "For each in-scope region, obtained the list of DB instances by calling the describe_db_instances() boto3 command.",
            "Saved the list of DB instances (RDS/[region_name]/db_instances.json).",
            "Inspected the database configuration for each instance(s) to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["PubliclyAccessible must be False."],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instances are publicly accessible."
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
            "For each in-scope region, obtained the list of DB instances by calling describe_db_instances() boto3 command.",
            "Saved the list of DB instances in the audit evidence folder (RDS/[region_name]/db_instances.json).",
            "For each DB instance, obtained its tags using list_tags_for_resource() boto3 command.",
            f"Inspected each DB instance to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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

            arn = db.get("DBInstanceArn")
            tags_response = audit.evidence_client.get_aws(
                f"RDS/{region}/db_instances/{db['DBInstanceIdentifier']}/tags.json",
                lambda: rds.list_tags_for_resource(ResourceName=arn)
            )

            actual_db_tags = {t["Key"]: t.get("Value", "") for t in tags_response.get("TagList", [])}

            evaluate_tags(sample, required_tags, actual_db_tags)
            control.samples.append(sample)

    control.evaluate_samples()
    if not control.result:
        control.result_description = (
            f"Exceptions Noted. {control.num_findings} RDS instance(s) missing required tags or have empty values."
        )

    return control

def test_rds_backup_retention(audit, control_id, risk_rating=1):
    control_config = audit.config.get("control_config") or {}
    required_rds_retention_days = control_config.get("rds_backup_retention_days", 14)
    control = Control(
        control_id=control_id,
        control_description=f"RDS backups are retained for at least {required_rds_retention_days} days.",
        test_procedures=[
            "For each in-scope region, obtained the list of DB instances by calling the describe_db_instances() boto3 command.",
            "Saved the list of DB instances (RDS/[region_name]/db_instances.json).",
            "Inspected the database configuration for each instance(s) to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=[f"BackupRetentionPeriod must be >= {required_rds_retention_days} days."],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instances do not have sufficient backup retention (at least {required_rds_retention_days} days)."    
    return control

def test_rds_auto_minor_version_upgrade(audit, control_id, risk_rating=1):
    control = Control(
        control_id=control_id,
        control_description="RDS instances have automatic minor version upgrades enabled.",
        test_procedures=[
            "For each in-scope region, obtained the list of DB instances by calling the describe_db_instances() boto3 command.",
            "Saved the list of DB instances (RDS/[region_name]/db_instances.json).",
            "Inspected the database configuration for each instance to determine if automatic minor version upgrades are enabled."
        ],
        test_attributes=["AutoMinorVersionUpgrade = True."],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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
            "For each in-scope region, obtained the list of DB instances and DB clusters using describe_db_instances() and describe_db_clusters() boto3 commands.",
            "Saved the list of DB instances (RDS/[region_name]/db_instances.json) and DB clusters (RDS/[region_name]/db_clusters.json).",
            "Inspected each DB instance and associated cluster (if applicable) to determine if deletion protection is enabled."
        ],
        test_attributes=["DeletionProtection = True (cluster OR instance)."],
        audit=audit,
        table_headers=["Region", "DB Instance", "Result", "Comments"],
        risk_rating=risk_rating        
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        rds = boto3.client("rds", region_name=region)

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
            "Saved the list of instances in the audit evidence folder (EC2/[region_name]/instances.json).",
            "For each instance, obtained its tags from the 'Tags' attribute.",
            f"Inspected each EC2 instance to determine if the following tag keys exist and have non-empty values: {required_tags}"
        ],
        test_attributes=[],
        audit=audit,
        table_headers=["Region", "Instance ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = boto3.client("ec2", region_name=region)

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
            f"Exceptions Noted. {control.num_findings} EC2 instance(s) missing required tags or have empty values."
        )

    return control

def test_ebs_volume_encryption(audit, control_id, risk_rating=2):
    control = Control(
        control_id=control_id,
        control_description="EBS volumes are encrypted at rest.",
        test_procedures=[
            "For each in-scope region, obtained the list of EBS volumes by calling describe_volumes() boto3 command.",
            "Saved the list of volumes in the audit evidence folder (EC2/[region_name]/volumes.json).",
            "Inspected the configuration for each volume to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["Encrypted = True."],
        audit=audit,
        table_headers=["Region", "Volume ID", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = boto3.client("ec2", region_name=region)

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
        ec2 = boto3.client("ec2", region_name=region)

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
            f"Exceptions Noted. {control.num_findings} EBS volume(s) missing required tags or have empty values."
        )

    return control

def test_ebs_default_encryption(audit, control_id, risk_rating=0):
    # NOTE: Risk rating is set to 'Informational'. Not having this set does not mean there are unencrypted EBS volumes.
    control = Control(
        control_id=control_id,
        control_description="EBS volumes must have default encryption enabled in each region.",
        test_procedures=[
            "For each in-scope region, checked if EBS default encryption is enabled using get_ebs_encryption_by_default() boto3 command.",
            "Saved the results in the audit evidence folder (EC2/[region_name]/default_ebs_encryption.json).",
            "Inspected the configuration for each region to determine compliance with the default encryption setting."
        ],
        test_attributes=["EbsEncryptionByDefault = True."],
        audit=audit,
        table_headers=["Region", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    for region in audit.in_scope_regions:
        ec2 = boto3.client("ec2", region_name=region)

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

def test_cloudtrail_global_logging(audit, control_id, risk_rating=3):
    control = Control(
        control_id=control_id,
        control_description="At least one multi-region CloudTrail trail has logging enabled.",
        test_procedures=[
            "Obtained CloudTrail trails using the describe_trails() boto3 command.",
            "Saved the trail configuration in the audit evidence folder (CloudTrail/trails.json).",
            "Obtained the status of each multi-region trail using the get_trail_status() boto3 command.",
            "Saved the trail status in the audit evidence folder (CloudTrail/[trail_name]/status.json).",
            "Inspected the trail configuration and status to determine if at least one multi-region trail has logging enabled."
        ],
        test_attributes=[
            "At least one trail must have IsMultiRegionTrail = True and IsLogging = True."
        ],
        audit=audit,
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = boto3.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        control.result = False
        control.result_description = "No CloudTrails founds."
        return control

    found_valid_trail = False
    for trail in trails:
        if not trail.get("IsMultiRegionTrail", False):
            continue
        status = audit.evidence_client.get_aws(
            f"CloudTrail/{trail['Name']}/status.json",
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
            "Inspected each trail's configuration to determine if log file validation is enabled."
        ],
        test_attributes=[
            "LogFileValidationEnabled must be True for all trails."
        ],
        audit=audit,
        table_headers=["Trail Name", "Result", "Comments"],
        risk_rating=risk_rating
    )

    if control.is_excluded:
        return control

    ct = boto3.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.describe_trails(includeShadowTrails=False)
    ).get("trailList", [])

    if not trails:
        control.result = False
        control.result_description = "No CloudTrails configured."
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
            "Obtained a list of CloudTrails by calling the list_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (CloudTrail/trails.json).",
            "For each trail, obtained the S3 bucket name and checked the bucket's public access block settings using get_public_access_block() boto3 command.",
            "Saved the public access block settings for each bucket in the audit evidence folder (CloudTrail/buckets/[bucket_name]/public_access_block.json).",
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

    ct = boto3.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.list_trails()
    ).get("Trails", [])

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
            f"CloudTrail/buckets/{bucket_name}/public_access_block.json",
            lambda: boto3.client("s3").get_public_access_block(Bucket=bucket_name),
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
            f"Exceptions Noted. {control.num_findings} CloudTrail bucket(s) are not fully protected."
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
            "Obtained a list of CloudTrails by calling the list_trails() boto3 command.",
            "Saved the list of trails in the audit evidence folder (CloudTrail/trails.json).",
            "For each trail, called get_trail_status() to check IsLogging and StopLoggingTime.",
            f"Saved each trail's status in the audit evidence folder (CloudTrail/trails_status/[trail_name].json).",
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

    ct = boto3.client("cloudtrail")
    trails = audit.evidence_client.get_aws(
        "CloudTrail/trails.json",
        lambda: ct.list_trails()
    ).get("Trails", [])

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
            f"CloudTrail/trails_status/{trail_name}.json",
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
            f"Exceptions Noted. {control.num_findings} trail(s) have logging stopped "
            f"currently or within the last {lookback_days} days."
        )

    return control
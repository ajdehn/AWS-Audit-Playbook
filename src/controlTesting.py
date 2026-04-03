from dataclasses import dataclass, field
from typing import List, Dict, Optional
from utils import is_sample_excluded, is_control_excluded, process_sample_exclusion
import boto3
import botocore
from datetime import datetime, timezone

# NOTE: Result is set to "False" until logic determines sample meets testing criteria.
@dataclass
class Sample:
    sample_id: Dict
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
    audit: object
    table_headers: Optional[List[str]] = None
    include_sample_number: bool = False
    samples: List["Sample"] = field(default_factory=list)
    result: bool = True
    result_description: str = ""
    num_findings: int = 0
    num_exclusions: int = 0
    total_population: int = 0
    is_excluded: bool = False

    def __post_init__(self):
        # Set exclusion status AFTER object is created
        self.is_excluded = is_control_excluded(
            self.control_id,
            self.audit.config
        )

        if self.is_excluded:
            self.result = False
            self.result_description = "Control is excluded. See exclusions.json"

    def __str__(self):
        return (
            f"control_id: {self.control_id}\n"
            f"control_description: {self.control_description}\n"
            f"is_excluded: {self.is_excluded}\n"
            f"result: {'Pass' if self.result else 'Fail'}\n"
            f"result_description: {self.result_description}\n"
        )

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
            return self

        # Count findings (failures)
        self.num_findings = sum(1 for s in in_scope_samples if not s.result)

        # Final result
        self.result = self.num_findings == 0
        return self

def test_s3_encryption(audit, control_id):
    control = Control(
        control_id=control_id, audit=audit,
        control_description="S3 buckets are encrypted at rest.",
        test_procedures=[
            "Obtained a list of S3 buckets by calling the list_buckets() boto3 command.",
            "Saved the list of S3 buckets in the audit evidence folder (S3/buckets.json).",
            "Obtained the encryption settings for each bucket by calling the get_bucket_encryption() boto3 command.",
            "Saved the encryption settings for each S3 bucket (S3/[bucket_name]/encryption.json).",
            "Inspected the encryption settings for each bucket to determine if they comply with the test attribute(s) below."
        ],
        test_attributes=["ServerSideEncryptionConfiguration is present in encryption.json."],
        table_headers=["Bucket Name", "Result", "Comments"]
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

def test_s3_public_access(audit, control_id):
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
        table_headers=["Bucket Name", "Result", "Comments"]
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

def test_iam_password_policy(audit, control_id):
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
        audit=audit
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

def test_root_no_access_keys(audit, control_id):
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
        audit=audit
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

def test_root_mfa_enabled(audit, control_id):
    control = Control(
        control_id=control_id,
        control_description="Root account has MFA enabled.",
        test_procedures=[
            "Obtained the AWS account summary by calling the get_account_summary() boto3 command.",
            "Saved the account summary in the audit evidence folder (IAM/account_summary.json)"
            "Inspected the account summary to determine if it complies with the test attribute(s) below."
        ],
        test_attributes=[
            "AccountMFAEnabled must be 1."
        ],
        audit=audit
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

def test_iam_access_key_age(audit, control_id):
    control_config = audit.config.get("control_config") or {}
    max_age_days = control_config.get("iam_key_max_age", 365)

    control = Control(
        control_id=control_id,
        control_description=f"IAM access keys are rotated at least every {max_age_days}.",
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
        table_headers=["User", "Access Key ID", "Result", "Comments"]
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
    TODO: Move logic to when audit is created and save in_scope_regions variable.
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
    in_scope_regions = control_config.get("in_scope_regions", [])
    in_scope_regions = [r.lower() for r in in_scope_regions]

    if not in_scope_regions:
        # in_scope_regions not set in config value. Return available regions.
        return sorted(available_regions)

    # Check for invalid regions
    in_scope_set = set(in_scope_regions)
    invalid_regions = in_scope_set - available_regions
    if invalid_regions:
        raise ValueError(
            f"Invalid regions in config: {sorted(invalid_regions)}. "
            f"Valid regions are: {sorted(available_regions)}"
        )

    # Return validated regions
    return [r for r in in_scope_regions if r in available_regions]


def test_rds_encryption(audit, control_id):
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
        table_headers=["Region", "DB Instance", "Result", "Comments"]
    )

    if control.is_excluded:
        return control

    for region in get_regions(audit):
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
                sample.comments = "Exceptions Noted. RDS instance is not encrypted."

            control.samples.append(sample)
    control.evaluate_samples()
    if not control.result:
        # Document exception language.
        control.result_description = f"Exceptions Noted. {control.num_findings} RDS instances are not encrypted."
    return control

def test_rds_public_access(audit, control_id):
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
        table_headers=["Region", "DB Instance", "Result", "Comments"]
    )

    if control.is_excluded:
        return control

    for region in get_regions(audit):
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


def test_rds_backup_retention(audit, control_id):
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
        table_headers=["Region", "DB Instance", "Result", "Comments"]
    )

    if control.is_excluded:
        return control

    for region in get_regions(audit):
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
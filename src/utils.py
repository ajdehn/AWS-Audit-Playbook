import json
import os
import shutil
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

def create_session(session_name="auditops-assume-role"):
    load_dotenv()

    role_arn = os.getenv("role_arn")
    external_id = os.getenv("external_id")

    # Normalize empty strings → None
    role_arn = role_arn.strip() if role_arn else None
    external_id = external_id.strip() if external_id else None

    # No role provided, use default credentials.
    if not role_arn and not external_id:
        return boto3.Session()

    # Check if role_arn and external_id are set.
    if not role_arn or not external_id:
        raise ValueError(
            "Both 'role_arn' and 'external_id' must be set in the environment to assume a role."
        )

    # Assume role
    try:
        sts = boto3.client("sts")
        response = sts.assume_role(
            RoleArn=role_arn,
            ExternalId=external_id,
            RoleSessionName=session_name
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]

        raise RuntimeError(
            f"Failed to assume IAM role.\n"
            f"RoleArn: {role_arn}\n"
            f"ErrorCode: {error_code}\n"
            f"Message: {error_msg}"
        ) from e

    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def get_aws_account_id(session):
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def get_in_scope_regions(audit):
    """Return validated in-scope AWS regions based on config or account defaults."""

    regions = audit.evidence_client.get_aws(
        "ec2/regions.json",
        service="ec2",
        method="describe_regions",
        method_kwargs={
            "AllRegions": True,
            "Filters": [
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"]
                }
            ]
        }
    )

    available = {r["RegionName"] for r in regions["Regions"]}

    config_regions = [
        r.lower()
        for r in (audit.config.get("test_config") or {}).get("in_scope_regions", [])
    ]

    # No config override → return all regions
    if not config_regions:
        return sorted(available)

    invalid = set(config_regions) - available
    if invalid:
        raise ValueError(
            f"Invalid regions in config: {sorted(invalid)}. "
            f"Valid regions are: {sorted(available)}"
        )

    return sorted(config_regions)

"""
    Saves a json file to a specified path
"""
def save_json(extract, file_path):
    # isolating out the directory path to the file and creating the directory
    brokenUpPath = file_path.split('/')
    dirPathToFile = '/'.join(brokenUpPath[:len(brokenUpPath) - 1])
    # Create file path if it doesn't already exist.
    if not os.path.exists(dirPathToFile):
        os.makedirs(dirPathToFile)

    with open(file_path, 'w') as f:
        json.dump(extract, f, indent=4, default=str)

def load_json(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Invalid JSON file. File path {file_path}")
            return None
    return None

def load_config(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Handle empty config file.
        print(f"Warning: Config file not found: {file_path}")
        return {}
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in config: {file_path}")

"""
Returns True if the test is excluded.
"""
def is_test_excluded(test_id, config):
    exclusion = config.get("test_exclusions", {}).get(test_id, {})
    if not exclusion:
        return False     
    return is_exclusion_active(exclusion)

"""
Returns True if exclusion is active and valid.
"""
def is_exclusion_active(exclusion):
    if not isinstance(exclusion, dict):
        return False  # Invalid exclusion configurations.

    today = datetime.now(timezone.utc).date()
    if exclusion.get("permanent"):
        return True
    exp_date = exclusion.get("expiration_date")
    if exp_date:
        try:
            exp_date = datetime.strptime(exp_date, "%Y-%m-%d").date()
            return exp_date >= today
        except ValueError:
            print(f"Invalid Exclusion Date Format: {exclusion}")
            return False

    return False

def confirm_delete_folder(folder_path):
    if os.path.exists(folder_path):
        confirm = input(f"Folder '{folder_path}' exists. Do you want to delete it? (y/N): ").strip().lower()
        
        if confirm == "y":
            shutil.rmtree(folder_path)
            print("Deleting old evidence folder.")
        elif confirm == "n":
            print("Using cached evidence.")
        else:
            print("Invalid character. Folder not deleted.")

"""
Evaluates required tags against resource tags (S3, RDS, EC2, etc).

Args:
    sample (Sample): The sample object to update with results.
    required_tags (list): List of required tag keys.
    resource_tags (dict): Dictionary of tag key/value pairs from the resource.

Returns:
    None. Updates sample.is_passing and sample.comments in-place.
"""
def evaluate_tags(sample, required_tags, actual_resource_tags):
    # Normalize keys to lowercase for comparison
    actual_resource_tags_lower = {k.lower(): v for k, v in actual_resource_tags.items()}

    missing_tags = []
    empty_tags = []

    for key in required_tags:
        key_lower = key.lower()
        if key_lower not in actual_resource_tags_lower:
            missing_tags.append(key)
        elif actual_resource_tags_lower[key_lower].strip() == "":
            empty_tags.append(key)

    if not missing_tags and not empty_tags:
        sample.is_passing = True
    else:
        if missing_tags:
            sample.comments += f"Missing tags: {missing_tags}. "
        if empty_tags:
            sample.comments += f"Empty tag values: {empty_tags}."
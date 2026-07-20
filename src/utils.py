import json
import os
import platform
import shutil
from datetime import datetime, timezone, date
import boto3
from botocore.exceptions import ClientError
import requests
from pathlib import Path
from dotenv import load_dotenv

def create_session(session_name="auditops-assume-role"):
    load_dotenv()

    role_arn = os.getenv("role_arn", "").strip()
    external_id = os.getenv("external_id", "").strip()

    # Normalize empty strings → None
    role_arn = role_arn.strip() if role_arn else None
    external_id = external_id.strip() if external_id else None

    # No role provided, use local credentials.
    if not role_arn and not external_id:
        return boto3.Session()

    # Check if role_arn and external_id are set.
    if not (role_arn and external_id):
        raise ValueError("Both 'role_arn' and 'external_id' must be set in the environment to assume a role.")
    
    creds = assume_role(role_arn, external_id, session_name)
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def assume_role(role_arn, external_id, session_name):
    sts = boto3.client("sts")
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            ExternalId=external_id,
            RoleSessionName=session_name
        )
    except ClientError as e:
        raise RuntimeError(
            f"Failed to assume role {role_arn}: "
            f"{e.response['Error']['Message']}"
        ) from e

    return response["Credentials"]

def upload_to_audit_portal(client_email: str, auditor_email: str, upload_portal_link: str):

    # Step 1: Zip audit evidence folder
    zip_file = shutil.make_archive("tmp/audit_evidence", "zip", "tmp/audit_evidence")

    # Step 2: Upload evidence to auditor's portal
    with open(zip_file, "rb") as f:
        response = requests.post(
            upload_portal_link,
            data={"client_email": client_email, "auditor_email": auditor_email},
            files={"file": ("audit_evidence.zip", f, "application/zip")},
            timeout=60
        )
    
    try:
        response.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to upload evidence to {upload_portal_link}") from e
    finally:
        # Delete zip file after it's been uploaded.
        if os.path.exists(zip_file):
            os.remove(zip_file)
     
    return response.json() 

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
def save_json(data, file_path):
    path = Path(file_path).resolve()

    #Bypass Windows MAX_PATH limit, if needed
    if platform.system() == "Windows":
        path_str = str(path)
        if not str(path).startswith("\\\\?\\"):
            win_path = f"\\\\?\\{path}"
            os.makedirs(os.path.dirname(win_path), exist_ok=True)

            # Open the file using the string path
            with open(win_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, default=str)
            return

    #Standard workflow if short path name, or on Mac or Linux    
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=str)

def load_json(file_path):
    path = Path(file_path)
    if not path.exists():
        return None
    try:
        with path.open() as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Invalid JSON file: File path {file_path}")
        return None

def load_config(file_path, audit):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            # Build sample exclusion index
            sample_exclusion_index = {}
            for item in data["sample_exclusions"]:
                test_id = item["test_id"]
                # Convert sample_id dict into a hashable tuple
                sample_key = tuple(sorted(item["sample_id"].items()))
                sample_exclusion_index[(test_id, sample_key)] = item
            audit.sample_exclusion_index = sample_exclusion_index

            # Build test exclusion index
            test_exclusion_index = {}
            for item in data["test_exclusions"]:
                test_exclusion_index[item["test_id"]] = item
            audit.test_exclusion_index = test_exclusion_index

            return data

    except FileNotFoundError:
        # Handle empty config file.
        print(f"Warning: Config file not found: {file_path}")
        return {}
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in config: {file_path}")

def is_test_excluded(test_id, audit):
     # Returns true if test is excluded in the config file.
    if audit.test_exclusion_index:
        exclusion = audit.test_exclusion_index.get(test_id)
        if exclusion is not None:
            if exclusion["permanent"]:
                return True
            else:
                # Check if exclusion is current
                exp = exclusion["expiration_date"]
                if exp and date.fromisoformat(exp) >= date.today():
                    return True
                else:
                    return False
    else:
        return False

def confirm_delete_folder(folder_path):
    if not os.path.exists(folder_path):
        return
    
    confirm = input(f"Folder '{folder_path}' exists. Do you want to delete it? (y/N): ").strip().lower()

    if confirm == "y":
        shutil.rmtree(folder_path)
        print(f"Deleted '{folder_path}' folder.")
    elif confirm == "n":
        print("Using cached evidence.")
    else:
        print(f"Invalid character. Did not delete '{folder_path}' folder.")

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
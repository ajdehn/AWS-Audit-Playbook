import json
import os
import shutil
from datetime import datetime, timezone
import boto3
from dotenv import load_dotenv

def create_session(session_name="auditops-assume-role"):
    load_dotenv()
    use_iam_role = os.getenv("use_iam_role", "false").lower() == "true"

    # Not using IAM role.
    if not use_iam_role:
        return boto3.Session()

    role_arn = os.getenv("role_arn")
    external_id = os.getenv("external_id")
    # Use IAM role.
    sts = boto3.client("sts")
    response = sts.assume_role(
        RoleArn=role_arn,
        ExternalId=external_id,
        RoleSessionName=session_name
    )
    creds = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def get_aws_account_id(audit):
    sts = audit.session.client("sts")
    return sts.get_caller_identity()["Account"]

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

def load_json_if_exists(file_path):
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
        raise ValueError(f"Config file not found: {file_path}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in config: {file_path}")

"""
Returns True if the control is excluded.
"""
def is_control_excluded(control_id, config):
    for e in config.get("control_exclusions", {}).get(control_id, []):
        if is_exclusion_active(e):
            return True
    return False

"""
Returns True if exclusion is active.
"""
def is_exclusion_active(exclusion):
    today = datetime.now(timezone.utc).date()
    if exclusion.get("permanent"):
        return True
    exp_date = exclusion.get("expiration_date")
    if exp_date:
        exp_date = datetime.strptime(exp_date, "%Y-%m-%d").date()
        return exp_date >= today

    return False

def process_sample_exclusion(control, sample, audit):
    for e in audit.config.get("sample_exclusions", {}).get(control.control_id, []):
        config_sample_id = e.get("sample_id", {})

        if all(sample.sample_id.get(k) == v for k, v in config_sample_id.items()):
            if is_exclusion_active(e):
                sample.is_excluded = True
                sample.comments = "Sample is excluded. See config.json"
                control.samples.append(sample)
                return True

    return False

def process_control_pass_fail(sample, condition, fail_msg):
    if condition:
        sample.result = True
    else:
        sample.comments = fail_msg

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
    None. Updates sample.result and sample.comments in-place.
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
        sample.result = True
    else:
        if missing_tags:
            sample.comments += f"Missing tags: {missing_tags}. "
        if empty_tags:
            sample.comments += f"Empty tag values: {empty_tags}."
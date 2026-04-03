import json
import os
import shutil
from datetime import datetime, timezone

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
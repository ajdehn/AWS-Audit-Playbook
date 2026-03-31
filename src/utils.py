import json
import os
import shutil
from datetime import datetime, timezone

"""
    Saves a json file to a specified path
"""
def save_json(extract, filePath):
    # isolating out the directory path to the file and creating the directory
    brokenUpPath = filePath.split('/')
    dirPathToFile = '/'.join(brokenUpPath[:len(brokenUpPath) - 1])
    # Create file path if it doesn't already exist.
    if not os.path.exists(dirPathToFile):
        os.makedirs(dirPathToFile)

    with open(filePath, 'w') as f:
        json.dump(extract, f, indent=4, default=str)
    f.close()

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
    with open(file_path, "r") as f:
        return json.load(f)

"""
Returns True if the control is excluded.
"""
def is_control_excluded(control_id, config):
    for e in config["control_exclusions"].get(control_id, []):
        if is_exclusion_active(e):
            return True
    return False

"""
Returns True if exclusion is active.
"""
def is_exclusion_active(exclusion):
    today = datetime.utcnow().date()
    if exclusion.get("permanent"):
        return True
    exp_date = exclusion.get("expiration_date")
    if exp_date:
        exp_date = datetime.strptime(exp_date, "%Y-%m-%d").date()
        return exp_date >= today
    return False

def check_sample_exclusion(control_id, sample, config):
    if is_sample_excluded(control_id, sample, config):
        sample.is_excluded = True
        sample.comments = "Sample is excluded. See config.json"
        return sample
    return sample

"""
Returns True if a sample is excluded.
"""
def is_sample_excluded(control_id, sample, config):
    for e in config["sample_exclusions"].get(control_id, []):
        config_sample_id = e.get("sample_id", {})
        match_sample_id = sample.sample_id

        if all(match_sample_id.get(key) == value for key, value in config_sample_id.items()):
            if is_exclusion_active(e):
                return True

    return False

def confirm_delete_folder(folder_path):
    if os.path.exists(folder_path):
        confirm = input(f"Folder '{folder_path}' exists. Do you want to delete it? (y/N): ").strip().lower()
        
        if confirm == "y":
            shutil.rmtree(folder_path)
            print("Deleting old evidence folder.")
        elif confirm == "N":
            print("Using cached evidence.")
        else:
            print("Aborted. Folder not deleted.")
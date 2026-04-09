# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/). The goal of this project is to help auditors conduct **AWS audits, without screenshots**.

## Why use this project
- Auditors deserve high-quality evidence directly from AWS. Using this project, you can share JSON files directly from boto3.
- Taking screenshots is a waste of time for everyone, auditors included. This script takes **minutes** to gather the required evidence and generate the report.
- Screenshots don't cut it when cloud configurations change daily. I highly encourage you run this script daily (or weekly) to begin having high quality conversations with your DevOps team.

## Project Overview
- A read-only [script](./src/controlTesting.py) to generate and evaluate audit evidence (no screenshots required).
   - The script creates a new folder (tmp/audit_evidence) that you can zip and share with your auditor.
- A [report builder](./src/buildReport.py) to create the AWS audit report. This report is extremely transparent and shows when samples and controls are excluded.
   - Check out the [Sample Audit Report](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?usp=sharing).
- A [library](./evidence_library/) of example audit evidence created from the script with the supporting JSON files.
- List of [controls](./controls/) with detailed guidance of how to test each control.
- A [JSON audit report](./evidence_library/controls.json) which cleanly displays the test procedures and control findings.

## Setup Instructions
1. Pre-requisites: Install Git, Python, and the AWS CLI.
2. Clone the Github repository.
3. Install the dependencies via `pip install -r requirements.txt`
    * The playbook requires the boto3 library, v1.39 or newer.  This command will install boto3 and its dependencies.
4. Create an IAM user in the AWS account you want to audit.
   * User needs [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) permissions.
5. Create an access key for the IAM user created in Step 4: [AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html)
    * NOTE: Configure the access key on your local machine using the 'aws configure' command [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
    * NOTE: Access keys can only be viewed once, at the time of creation.  They must be stored securely elsewhere for future use.
6. Run the command 'python src/runAudit.py'
7. Optional: Create and populate the config file (example below). Use this to define control requirements (control_config) and exclude controls and samples that aren't in-scope.

```
{
  "control_config": {
    "in_scope_regions": ["us-east-1", "us-east-2"],
    "iam_password_min_length": 14,
    "iam_password_min_complexity_types": 4,
    "iam_password_require_expiration": false,
    "iam_password_max_password_age": null,
    "iam_password_password_history": 24,
    "iam_key_max_age": 90,
    "cloudtrail_logging_lookback_days": 365,
    "rds_backup_retention_days": 14,
    "base_required_tags": ["owner", "description", "classification"]
  },
  "control_exclusions": {
    "RDS Tags": {
      "rationale": "Only one RDS instance. We've decided tags aren't required.",
      "permanent": true,
      "expiration_date": null,
      "approvers": [
        "john.doe@acme.com"
      ]
    },
    "EBS Tags": {
      "rationale": "We've decided to only tag EC2 instances. Please check the associated instances",
      "permanent": false,
      "expiration_date": "2026-12-31",
      "approvers": [
        "john.doe@acme.com"
      ]
    }
  },
  "sample_exclusions": {
    "IAM User Key Age": [
      {
        "sample_id": {
          "user": "itauditguy",
          "access_key_id": "AKIA3TURCXF5GCAELVHX"
        },
        "rationale": "This is a very old access key for demo purposes.",
        "permanent": true,
        "expiration_date": null,
        "approvers": [
          "john.doe@acme.com"
        ]
      },
      {
        "sample_id": {
          "user": "anotheruser",
          "access_key_id": "AKIAEXAMPLE123"
        },
        "rationale": "Another test key to ignore",
        "permanent": false,
        "expiration_date": "2026-12-31",
        "approvers": [
          "john.doe@acme.com"
        ]
      }
    ],
    "S3 Public Access": [
      {
        "sample_id": {
          "bucket_name": "demo-bucket"
        },
        "rationale": "This bucket is intentionally public for testing",
        "permanent": false,
        "expiration_date": "2099-12-31",
        "approvers": [
          "john.doe@acme.com"
        ]
      }
    ]
  }
}
```

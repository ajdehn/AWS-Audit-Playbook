# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/). The goal of this project is to help auditors conduct **AWS audits, without screenshots**.

## Why use this project
- Auditors deserve high-quality evidence directly from AWS. Using this project, you will be able to share JSON files directly from boto3.
- Screenshots are a waste of time for everyone, auditors included. This script takes **minutes** to gather the required evidence and generate the report.
- Screenshots don't cut it when cloud configurations change daily. Auditors should be running this script daily (or at least weekly) and use it to start having risk-driven conversations with your Engineering teams.

## Project Overview
- A read-only [script](./src/controlTesting.py) to generate and evaluate audit evidence (no screenshots required).
   - The script creates a new folder (tmp/audit_evidence) that you can zip and share with your auditor.
- A [report builder](./src/buildReport.py) to create an [AWS Audit Report](./evidence_library/aws_audit_report.pdf).
- A [library](./evidence_library/) of example audit evidence created from the script with the supporting JSON files.
- List of [controls](./controls/) with detailed guidance of how to test each control.
- A [JSON audit report](./evidence_library/controls.json) is also included. This is a machine readable audit report and cleanly displays the test procedures and control findings.

## Setup Instructions
1. Install pre-requisites:
      * VS Code
         * [Windows Tutorial](https://www.youtube.com/watch?v=cu_ykIfBprI)
         * [Mac Tutorial](https://www.youtube.com/watch?v=DA03DODTP5w)
      * Git [Tutorial](https://www.youtube.com/watch?v=3Tsaxxv9sls)
      * Python [Tutorial](https://www.youtube.com/watch?v=D2cwvpJSBX4)
      * AWS CLI
         * [Windows Tutorial](https://www.youtube.com/watch?v=jCHOsMPbcV0)
         * [Mac Tutorial](https://www.youtube.com/watch?v=U0AmeqL4DfE)
2. Run the commands below to make sure everything is installed correctly (if not, please review the videos in Step 1).
   ```
   git --version
   python --version
   aws --version
   ```
3. Open your development folder in VS Code.
4. Clone the AWS Audit Playbook Github Repo
      * git clone https://github.com/ajdehn/AWS-Audit-Playbook.git
5. Switch to the AWS Audit Playbook folder
      * cd AWS-Audit-Playook
6. Create a virtual environment
      * python -m venv venv
      * * source venv/bin/activate
7. Install the dependencies via `pip install -r requirements.txt`
      * The playbook requires the boto3 library, v1.39 or newer.  This command will install boto3 and its dependencies.
8. Create an IAM user in the AWS account you want to audit.
      * User needs [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) permissions.
9. Create an access key for the IAM user created in Step 4: [AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html)
    * NOTE: Configure the access key on your local machine using the 'aws configure' command [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
    * NOTE: Access keys can only be viewed once, at the time of creation.  They must be stored securely elsewhere for future use.
10. Run the command 'python src/runAudit.py'. Running this scan will perform the following:
  * Create a tmp folder for the audit evidence and report.
  * Run all of the control tests (see [src/controlTesting.py](./src/controlTesting.py))
11. Optional: Configure the env file to run the script through an IAM role.
```
role_arn = "arn:aws:iam::111222333444:role/aws_audit_playbook"  # Update with your actual role arn.
external_id = "a1b2c3d4e5f6g7h8i9"  # Update with your actual external id.
```
12. Optional: Create and populate the config file (example below). Use this to define control requirements (control_config) and exclude controls and samples that aren't in-scope.
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

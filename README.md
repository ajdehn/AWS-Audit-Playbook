# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/). The goal of this project is to help auditors conduct **AWS audits, without screenshots**.

## Why use this project
- Auditors deserve high-quality evidence directly from AWS. Using this project, you will be able to share JSON files directly from boto3.
- Screenshots are a waste of time for everyone, auditors included. This script takes **minutes** to gather the required evidence and generate the report.
- Screenshots don't cut it when cloud configurations change daily. Auditors should be running this script daily (or at least weekly) and use it to start having risk-driven conversations with your Engineering teams.

## Project Overview
- A read-only [script](./src/aws_tests.py) to generate and evaluate audit evidence (no screenshots required).
   - The script creates a new folder (tmp/audit_evidence) that you can zip and share with your auditor.
- A [JSON audit report](./evidence_library/aws_audit_report.json). This is a machine readable audit report and cleanly displays the scope, test results, and configuration.
- A [report builder](./src/build_report.py) to create an [AWS Audit Report](./evidence_library/aws_audit_report.pdf).
- A [library](./evidence_library/) of example audit evidence created from the script with the supporting JSON files.
- List of [tests](./tests/) with detailed testing procedures.

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
2. Run these commands to check if everything is installed correctly. If you receive an error, go back to the videos in Step 1.
   ```
   git --version
   python --version
   aws --version
   ```
3. Open your development folder in VS Code.
4. Clone the AWS Audit Playbook Github Repo and switch to the new folder.
      
   ```
   git clone https://github.com/ajdehn/AWS-Audit-Playbook.git
   cd AWS-Audit-Playbook
   ```
5. Create a virtual environment and install dependencies.
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
6. Create an IAM user in the AWS management console.
      * The user needs [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) permissions.
7. Create an access key for the IAM user created in the previous step: [AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html)
    * NOTE: Configure the access key on your local machine using the 'aws configure' command [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
    * NOTE: Access keys can only be viewed once, at the time of creation.  They must be stored securely elsewhere for future use.
8. Run the command 'python src/run_audit.py'. Running this scan will perform the following:
  * Create a tmp folder for the audit evidence and report.
  * Run all tests (see [src/aws_tests.py](./src/aws_tests.py))
9. Optional: Configure the env file to run the script through an IAM role.
```
role_arn = "arn:aws:iam::111222333444:role/aws_audit_playbook"  # Update with your actual role arn.
external_id = "a1b2c3d4e5f6g7h8i9"  # Update with your actual external id.
```
10. Optional: Create and populate the config file (example below). Use this to define test requirements (test_config) and exclude tests and samples that aren't in-scope.
```
{
  "test_config": {
    "in_scope_regions": [],
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
  "test_exclusions": {
    "EXAMPLE TEST ID": {
      "rationale": "Based on discussion with DevOps, we agreed this test is not needed to mitigate risk.",
      "permanent": true,
      "expiration_date": null,
      "approvers": [
        "john.doe@acme.com"
      ]
    },
    "EXAMPLE TEST ID 2": {
      "rationale": "Engineering is currently implementing this test. Pausing monitoring until December 31st, 2026.",
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
        "expiration_date": "2026-12-31",
        "approvers": [
          "john.doe@acme.com"
        ]
      }
    ]
  }
}
```

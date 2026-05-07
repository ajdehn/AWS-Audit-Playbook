# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/). The goal of this project is to **standardize** evidence collection for AWS, and help auditors conduct **AWS audits, without screenshots**.

## Why use this project
- Auditors deserve consistent, high-quality evidence directly from AWS. Using this project, you will be able to share the required evidence via JSON files gathered from [boto3](https://docs.aws.amazon.com/boto3/latest/).
- Screenshots are a waste of time for everyone, auditors included. This script takes **minutes** to gather the required evidence and generate the report.
- Consistent, automated evidence collection is the biggest roadblock preventing us from achieving continuous monitoring. Once we achieve this, GRC teams will be able to have honest, risk-driven conversations with your Engineering teams.

## Project Overview
- Documentation:
   - [Test Library](./test_library/): Documentation for how to perform audit tests on various AWS services. Each test includes a test description, an example risk, and detailed test procedures with links to the [boto3](https://docs.aws.amazon.com/boto3/latest/) documentation.
   - [Evidence Library](./evidence_library/): Example audit evidence generated and saved in a consistent format.
- Logic / Python Scripts:
   - [run_audit.py](./src/run_audit.py): Builds config file, defines scope, and runs aws_tests.py.
   - [aws_tests.py](./src/aws_tests.py): Gathers evidence from boto3 (no screenshots required) and performs audit testing.
   - [build_report.py](./src/build_report.py): Builds a PDF version of the audit report (Ex. [aws_audit_report.pdf](./evidence_library/aws_audit_report.pdf)).
- Project Outputs:
   - [aws_audit_report.json](./evidence_library/aws_audit_report.json): Machine readable audit report that clearly displays the scope, test results, and configuration.
   - [aws_audit_report.pdf](./evidence_library/aws_audit_report.pdf): Human readable report for people that aren't ready for JSON.

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
  "metadata": {
    "approved_by": "AJ Dehn",
    "approval_date": "2026-04-30"    
  },
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
      "expiration_date": null
    },
    "EXAMPLE TEST ID 2": {
      "rationale": "Engineering is currently implementing this test. Pausing monitoring until December 31st, 2026.",
      "permanent": false,
      "expiration_date": "2026-12-31"
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
        "expiration_date": null
      },
      {
        "sample_id": {
          "user": "anotheruser",
          "access_key_id": "AKIAEXAMPLE123"
        },
        "rationale": "Another test key to ignore",
        "permanent": false,
        "expiration_date": "2026-12-31"
      }
    ],
    "S3 Public Access": [
      {
        "sample_id": {
          "bucket_name": "demo-bucket"
        },
        "rationale": "This bucket is intentionally public for testing",
        "permanent": false,
        "expiration_date": "2026-12-31"
      }
    ]
  }
}
```

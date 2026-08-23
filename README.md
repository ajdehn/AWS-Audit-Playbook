# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/). The goal of this project is to **standardize** evidence collection for AWS, and help auditors conduct **AWS audits, without screenshots**.

## Why use this project
- Auditors deserve consistent, high-quality evidence directly from AWS. Using this project, you will be able to share the required evidence via JSON files gathered from [boto3](https://docs.aws.amazon.com/boto3/latest/).
- Screenshots are a waste of time for everyone, auditors included. This script takes **minutes** to gather the required evidence and generate the report.
- Consistent, automated evidence collection is the biggest roadblock preventing us from achieving continuous assurance. Once we achieve this, GRC teams will be able to have honest, risk-driven conversations with your Engineering teams.

## Project Overview
- Documentation:
   - [Test Library](./test_library/): Explanation of how to perform audit tests on various AWS services. Each test includes a test description, an example risk, and detailed test procedures with links to the [boto3](https://docs.aws.amazon.com/boto3/latest/) documentation.
   - [Evidence Library](./evidence_library/): Example audit evidence generated and saved in a consistent format.
- Project Outputs:
   - [aws_audit_report.json](./evidence_library/aws_audit_report.json): Machine readable audit report that clearly displays the scope, test results, and configuration.
   - [aws_audit_report.pdf](./evidence_library/aws_audit_report.pdf): Easy to read report that can easily be shared with auditors, regulators, and customers (as long as the audit is done in "summary_mode").

## Setup Instructions
1. Install pre-requisites:
      * VS Code
         * [Windows Tutorial](https://www.youtube.com/watch?v=cu_ykIfBprI)
         * [Mac Tutorial](https://www.youtube.com/watch?v=DA03DODTP5w)
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
3. Open a new development folder in VS Code.
4. Create a virtual environment and install the [AuditOps Python library](https://pypi.org/project/auditops/).
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -U auditops
   ```
5. Create an IAM user:
  * Create an IAM user in the AWS management console.
    * The user needs [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) permissions.
6. Configure the AWS CLI
  * Create an access key for the IAM user created in the previous step: [AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html)
    * NOTE: Configure the access key on your local machine using the 'aws configure' command [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
    * NOTE: Access keys can only be viewed once, at the time of creation.  They must be stored securely elsewhere for future use.
7. Copy the code below and name the file *aws_example.py*.
    ```
   from auditops.core.models import Audit, AuditHelpers
   from auditops.providers.aws import AWSCollector, AWSTester, AWSConfig
   from auditops.core.utils import aws_create_session
   import boto3
   from datetime import datetime
   
   def main():
       session = aws_create_session()
       aws_config = AWSConfig(in_scope_regions=['us-east-1'])
       helpers = AuditHelpers.create()
   
       audit = Audit(helpers = helpers, title = "AWS Audit Report", config=aws_config, auditor_name = "Happy Gilmore",
       audit_folder = "aws", delete_cached_evidence=True, summary_mode=True, exclusions=None)
   
       audit.run(collector=AWSCollector(session), tester=AWSTester())
   
   if __name__ == "__main__":
       main()

    ```
7. Run the command 'python aws_example.py'. Running this scan will perform the following:
  * Create a tmp folder for the audit evidence and report.
  * Run all tests (see [src/aws_tests.py](./src/aws_tests.py))
8. A new folder will be created for the audit. Within that folder, the library will collect and store the evidence in the 'audit_evidence' folder. Once collected, it will begin performing the testing and the audit reports will be stored in the 'reports' folder.
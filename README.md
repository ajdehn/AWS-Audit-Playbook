# Author
The AWS-Audit-Playbook is written and maintained by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/).

## Project Goals
1. Improve audit quality by documenting audit procedures, and sharing example evidence and audit reports.
2. Save **both** auditors and engineers currently spent on manual evidence collection.
3. Improve standardization and cloud security outcomes through high-quality audits.

## Project Overview
- [Test Library](./test_library/): Explanation of how to perform audit tests on various AWS services. Each test includes a test description, an example risk, and detailed test procedures with links to the [boto3](https://docs.aws.amazon.com/boto3/latest/) documentation.
- [Evidence Library](./evidence_library/): Example audit evidence generated and saved from the [AuditOps Python Library](https://pypi.org/project/auditops/).
- Project Outputs:
   - [aws_audit_report.pdf](./evidence_library/aws_audit_report.pdf): Report generated from the  can easily be shared with auditors, regulators, and customers (as long as the audit is done in "summary_mode").
   - [aws_audit_report.json](./evidence_library/aws_audit_report.json): Machine readable audit report that clearly displays the scope, test results, and configuration.
- [training.itauditguy.com](https://training.itauditguy.com/): Free web app that emails you credentials to login to an AWS sandbox.
- [AuditOps Python Library](https://pypi.org/project/auditops/): Open-source Python script that helps you automatically collect the required evidence in ~25 lines of code.


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
  * Option 1: Create an IAM user in your AWS Account:
    * The user needs [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) permissions.
  * Option 2: If you don't have an AWS account, enter your email into the form on [training.itauditguy.com](https://training.itauditguy.com/). This will send you credentials to an IAM user in a Sandbox AWS environment.
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

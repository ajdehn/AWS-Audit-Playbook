# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/). The goal of this project is to help auditors conduct **AWS audits, without screenshots**.

# Summary
To accomplish this vision, we are building the following:
- A read-only [script](./gatherAwsEvidence.py) to generate JSON files directly from AWS (no screenshots required) without affecting your environment.
- A [library](./evidence_library/) of audit evidence created from the script with example JSON files.
- List of [controls](./controls/) with detailed guidance of how to test each control.
- An example [audit workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?usp=sharing) to document audit results.

# Setup Instructions
1. Install the dependencies via `pip install -r requirements.txt`
    * The playbook requires the boto3 library, v1.39 or newer.  This command will install boto3 and its dependencies.
2. Create an IAM user in the AWS account you want to audit. Attach the [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) policy to the user.
    * AWS Best Practices recommend attaching policies first to a group and then adding the user, as opposed to attaching policies directly to the user.  Creating a group and attaching the SecurityAudit policy can be completed during user creation, if manually creating an IAM user for this script.
    * NOTE: The [script](./gatherAwsEvidence.py) can also be configured to run through an IAM role. This would require auditors to maintain a separate AWS account, so this will be released as part of a future version of the project.
3. Create an access key for the IAM user created in Step 2: [AWS Docs](https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html)
    * NOTE: Access keys can only be viewed once, at the time of creation.  They must be stored securely elsewhere for future use.
4. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
5. Configure the access key created in Step 3 on your local machine using the 'aws configure' command [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
6. Configure the auditScope variable in gatherAwsEvidence.py. Specify which regions are in-scope, and set controls that are out of scope as "False" to avoid collecting unnecesary evidence.
7. Run the command 'python gatherAwsEvidence.py'

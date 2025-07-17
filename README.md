# About
This playbook was written by [AJ Dehn](https://www.linkedin.com/in/ajdehn/). The goal of this project is to help auditors conduct **AWS audits, without screenshots**.

# Summary
To accomplish this vision, we are building the following:
- A [script](./gatherAwsEvidence.py) to generate JSON files directly from AWS (no screenshots required).
- List of [controls](./controls/) with detailed guidance of how to test each control.
- A [library](./evidence_library/) of audit evidence with example JSON files.
- An example [audit workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?usp=sharing) to document audit results.

# Setup Instructions
1. Install the dependencies via `pip install -r requirements.txt`
2. Create an IAM user in the AWS account you want to audit. Attach the [Security Audit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) policy to the user or grant the access through a group.
    * NOTE: The [script](./gatherAwsEvidence.py) can also be configured to run through an IAM role. This would require auditors to maintain a separate AWS account, so this will be released as part of a future version of the project.
3. Create an access key for the IAM user created in Step 2.
4. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
5. Configure the access key created in Step 3 on your local machine [Video Tutorial](https://youtu.be/RLx5qVZSTyE?si=7fqyxFzThDaB-mGQ).
6. Run the command 'python gather AwsEvidence.py'
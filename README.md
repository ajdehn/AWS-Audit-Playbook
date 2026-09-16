# Author
The AWS Audit Playbook is written and maintained by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/).

## Project Goals
1. Improve audit quality by documenting audit procedures, and sharing example evidence and audit reports.
2. Save **both** auditors and engineers currently spent on manual evidence collection.
3. Improve standardization and cloud security outcomes through high-quality audits.

## Project Overview
- **[Test Library](./test_library/)**: Explanation of how to perform audit testing on various AWS services. Each test includes a test description, an example risk, and detailed test procedures with links to the [boto3](https://docs.aws.amazon.com/boto3/latest/) documentation.
- **[Evidence Library](./evidence_library/)**: Example audit evidence generated and saved from the [AuditOps Python Library](https://pypi.org/project/auditops/).
- **[AuditOps Python Library](https://pypi.org/project/auditops/)**: Open-source Python script that helps you automatically collect the required evidence in ~25 lines of code.
- **[training.itauditguy.com](https://training.itauditguy.com/)**: Free web app that emails you credentials to login to an AWS sandbox.

## Project Outputs:
   - [Audit Report (PDF)](./evidence_library/aws_audit_report.pdf)
   - [Audit Report (JSON)](./evidence_library/aws_audit_report.json)

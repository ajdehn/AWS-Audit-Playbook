## Author
The AWS Audit Playbook is written and maintained by [AJ Dehn](https://www.linkedin.com/in/ajdehn/) founder of [AuditOps.io](https://www.auditops.io/).

## Project Goals
1. Improve audit quality by standardizing test procedures, providing example evidence, and sharing sample audit reports.
2. **Eliminate** screenshots and guesswork from the audit process. There should be no surprises about what evidence is required and how audit testing is performed.
3. Improve organization's cloud security posture. This can be accomplished when auditors and TPRM teams perform high quality audits.
4. Move the industry towards continuous assurance. It is **irresponsible** to check for high-risk misconfigurations (MFA, encryption, etc) once per year.

## Project Overview
- **[Test Library](./test_library/)**: Detailed explanation of how audit tests are performed. Each test includes an example risk, test procedures, and links to sample evidence.
- **[Evidence Library](./evidence_library/)**: Example audit evidence generated directly from a cloud providers API / SDK (ex. [Boto3](https://docs.aws.amazon.com/boto3/latest/), [GitHub Rest API](https://docs.github.com/en/rest), and [Google Workspace API](https://developers.google.com/workspace).
- **[AuditOps-SDK](https://pypi.org/project/auditops/)**: Open-source Python script that generates evidence, performs testing, and builds audit reports in ~25 lines of code.
- **[AWS Training Portal](https://training.itauditguy.com/)**: Gives **everyone** a chance to login to an AWS sandbox environment.

## Resources:
   - AWS
      - [AWS Evidence Library](./evidence_library/aws/audit_evidence)
      - [AWS Test Library](./test_library/aws/README.md)
      - [Example Audit Reports (PDF + JSON)](./evidence_library/aws/reports)
   - GitHub
      - [GitHub Evidence Library](./evidence_library/github/audit_evidence)
      - [GitHub Test Library](./test_library/github/README.md)
      - [Example Audit Reports (PDF + JSON)](./evidence_library/github/reports)

from dotenv import load_dotenv
import controlTesting
from utils import confirm_delete_folder, save_json, load_config
from buildReport import generate_pdf_report
from evidenceClient import EvidenceClient

class Audit:
    """
    Initializes the audit instance with the provided attributes.
    """
    def __init__(self, evidence_folder="tmp/audit_evidence",
    config_file_path="config.json"):
        self.evidence_folder = evidence_folder                      # Name of the evidence_folder
        self.config = load_config(config_file_path)                 # Control and sample exclusions
        self.evidence_client = EvidenceClient(base_path=evidence_folder, debug=False)

if __name__ == "__main__":
    # Load variables from .env file
    load_dotenv()
    audit = Audit()

    print("Running the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")
    controls = []

    # TODO: Check if control is excluded before performing testing.
    confirm_delete_folder(audit.evidence_folder)

    controls.append(controlTesting.test_s3_encryption(audit, "S3 Encryption"))
    controls.append(controlTesting.test_s3_public_access(audit, "S3 Public Access"))
    controls.append(controlTesting.test_iam_password_policy(audit, "IAM Password"))
    controls.append(controlTesting.test_root_mfa_enabled(audit, "IAM Root MFA"))
    controls.append(controlTesting.test_root_no_access_keys(audit, "IAM Root Access Key"))

    controls.append(controlTesting.test_iam_access_key_age(audit, "IAM User Key Age"))
    controls.append(controlTesting.test_rds_backup_retention(audit, "RDS Backup Retention"))
    controls.append(controlTesting.test_rds_encryption(audit, "RDS Encryption"))
    controls.append(controlTesting.test_rds_public_access(audit, "RDS Public Access"))

    # TODO: Add control criticality / severity score (High, Medium, Low, Informational)
    # TODO: Add default settings (new EBS volumes encrypted by default)
    # TODO: Add CloudTrail configuration checks (log-file validation, multi-region, etc)
    # TODO: Add S3 object owner check
    # TODO: Add encryption checks (EBS)
    # TODO: Add Tagging Controls (RDS, S3, EC2, EBS)
    # TODO: Add IAM tests (IAM User MFA, IAM User Unused Keys)
    # TODO: Add GuardDuty tests (GuardDuty Enabled, GuardDuty Alert Resolution)

    generate_pdf_report(audit, controls, "AWS", file_name="tmp/aws_audit_report.pdf")
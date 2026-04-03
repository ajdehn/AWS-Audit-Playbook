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

    controls.append(controlTesting.test_s3_encryption(audit, "C1000"))
    controls.append(controlTesting.test_s3_public_access(audit, "C1010"))
    controls.append(controlTesting.test_iam_password_policy(audit, "C1110"))
    controls.append(controlTesting.test_root_mfa_enabled(audit, "C1120"))
    controls.append(controlTesting.test_root_no_access_keys(audit, "C1130"))

    controls.append(controlTesting.test_iam_access_key_age(audit, "C1140"))
    controls.append(controlTesting.test_rds_backup_retention(audit, "C1300"))
    controls.append(controlTesting.test_rds_encryption(audit, "C1310"))
    controls.append(controlTesting.test_rds_public_access(audit, "C1310"))

    generate_pdf_report(audit, controls, "AWS", file_name="tmp/aws_audit_report.pdf")
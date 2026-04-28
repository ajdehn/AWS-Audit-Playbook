import aws_tests
from utils import confirm_delete_folder, save_json
from build_report import generate_pdf_report
import json
from audit import Audit

if __name__ == "__main__":
    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")

    tmp_folder_name = "tmp"
    # Confirm if you want to delete contents of the tmp folder (Select "N" to used cached evidence).
    confirm_delete_folder(tmp_folder_name)

    audit = Audit(tmp_folder=tmp_folder_name)
    audit.test_results = aws_tests.run_all_tests(audit)

    # Save audit report (JSON and PDF version).
    save_json(audit.to_dict(), f"{tmp_folder_name}/aws_audit_report.json")
    print(f"Report generated: {tmp_folder_name}/aws_audit_report.json")
    generate_pdf_report(audit, audit.test_results, "AWS", file_name=f"{tmp_folder_name}/aws_audit_report.pdf")

    # TODO: Support uploads to evidence repository (include PDF and supporting evidence).
from aws_tests import run_all_tests
from utils import (confirm_delete_folder, save_json, create_session, load_config, 
get_aws_account_id, get_in_scope_regions)
from build_report import generate_pdf_report
from audit import Audit

if __name__ == "__main__":
    print("\nRunning the AWS Audit Playbook (maintained by AJ Dehn - AuditOps.io)\n")

    tmp_folder_name = "tmp"
    # Confirm if you want to delete contents of the tmp folder (Select "N" to used cached evidence).
    confirm_delete_folder(tmp_folder_name)

    audit = Audit(tmp_folder=tmp_folder_name)
    audit.session = create_session()
    # TODO: Fully transfer audit.session to EvidenceClient.
    audit.evidence_client.session = audit.session
    audit.config = load_config("config.json")
    audit.aws_account_id = get_aws_account_id(audit.session)
    audit.in_scope_regions = get_in_scope_regions(audit)

    audit.test_results = run_all_tests(audit)

    # Save audit reports (JSON and PDF version).
    save_json(audit.to_dict(), f"{tmp_folder_name}/aws_audit_report.json")
    print(f"Report generated: {tmp_folder_name}/aws_audit_report.json")
    generate_pdf_report(audit, audit.test_results, "AWS", file_name=f"{tmp_folder_name}/aws_audit_report.pdf")

    # TODO: Support uploads to evidence repository (include PDF and supporting evidence).
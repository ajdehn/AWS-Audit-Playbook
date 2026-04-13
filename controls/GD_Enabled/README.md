## Control Description
GuardDuty is enabled for in-scope regions.

## Required Evidence
* [detectors.json](/evidence_library/GuardDuty/us-east-1/detectors.json) provides a list of detectors in a specific region.
  * This evidence is gathered by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/list_detectors.html) command in Boto 3.
* [config.json](/evidence_library/GuardDuty/us-east-1/26c236aa2c9a6cae9e1992402db1010c/config.json) provides information on the configuration of each detector.
  * This evidence is gathered by calling the [get_detectors()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/get_detector.html) command in Boto 3.

## Test Procedures
1. For each in-scope region, review the [detectors.json](/evidence_library/GuardDuty/us-east-1/detectors.json).
2. If the region has no detector ID's GuardDuty is not enabled in this region and the control has failed.
    1. [Example: Region with GuardDuty Detectors](/evidence_library/GuardDuty/us-east-1/detectors.json)
    2. [Example: Region WITHOUT GuardDuty Detectors](/evidence_library/GuardDuty/us-east-2/detectors.json)
3. Inspect the [GuardDuty/[region]/[detector_id]/config.json](/evidence_library/GuardDuty/us-east-1/26c236aa2c9a6cae9e1992402db1010c/config.json) to determine if at least one detector has has "Status": "ENABLED".
    * **Note:** It is your responsiblity to determine which regions are in-scope. At a minimum, you should include any region with an AWS resource (S3, RDS, EC2, etc).

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)

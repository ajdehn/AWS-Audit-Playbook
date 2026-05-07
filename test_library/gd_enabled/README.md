## Test Description
GuardDuty is enabled for in-scope regions.

## Example Risk
A malcious actor gains unauthorized access to your AWS account and is performing reconnaissance to figure out how they can exfiltrate sensitive data. This activity goes undetected, and causes a large scale security incident.

## Test Procedures
1. For each in-scope region, obtained a list of GuardDuty detectors by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty/client/list_detectors.html) boto3 command.  
2. For each in-scope region, saved the detector list: [guardduty/[region]/detectors.json](/evidence_library/guardduty/us-east-1/detectors.json).  
3. For each in-scope region, inspected `detectors.json` to determine whether any detector IDs exist.  
   - If no detector IDs are present, determined that GuardDuty is not enabled for the region and noted an exception.  
   1. [Example: Region with GuardDuty Detectors](/evidence_library/guardduty/us-east-1/detectors.json)  
   2. [Example: Region WITHOUT GuardDuty Detectors](/evidence_library/guardduty/us-east-2/detectors.json)  
4. For each detector ID identified, obtained detector configuration by calling the [get_detector()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty/client/get_detector.html) boto3 command.
5. For each detector ID, saved the detector configuration: [guardduty/[region]/[detector_id]/config.json](/evidence_library/guardduty/us-east-1/26c236aa2c9a6cae9e1992402db1010c/config.json).  
6. For each detector, inspected `config.json` to determine whether `"Status"` is set to `ENABLED`.

**Note:** It is your responsiblity to determine which regions are in-scope. At a minimum, you should include any region with an AWS resources (S3, RDS, EC2, etc).

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
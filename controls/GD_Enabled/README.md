## Control Description
GuardDuty findings are reviewed and responded to within the companies stated SLA's.

## Required Evidence
* [all_detectors.json](./example1.json) provides a list of detectors in an in-scope region.
  * This evidence is gathered by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/list_detectors.html) command in Boto 3.
* * [all_findings.json](./example1.json) provides a list of all GuardDuty findings for a specific detector.
  * This evidence is gathered by calling the [list_findings()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/list_findings.html) command in Boto 3.

## Testing Details
1. ???

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](google.com)
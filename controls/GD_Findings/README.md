## Control Description
GuardDuty findings are responded to within organization defined SLA's.

## Required Evidence
* [all_detectors.json](/evidence_library/CloudTrail/regions/us-east-1/all_detectors.json) provides a list of detectors in a specific region.
  * This evidence is gathered by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/list_detectors.html) command in Boto 3.
* [DETECTOR_ID_finding_stats.json](/evidence_library/CloudTrail/regions/us-east-1/DETECTOR_ID_findings_stats.json) provides information on the amount of active GuardDuty findings on that detector.
  * This evidence is gathered by calling the [get_finding_statistics()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/get_findings_statistics.html) command in Boto 3.

## Testing Details
1. For each in-scope region, review the [DETECTOR_ID_finding_stats.json](/evidence_library/CloudTrail/regions/us-east-1/DETECTOR_ID_finding_stats.json) file and confirm the following:
    * Confirm the "Status" is enabled at the detector level.
    * Confirm the following "DataSources" were enabled: "CloudTrail", "DNSLogs", "FlowLogs", and "S3Logs".
    * **Note:** It is your responsiblity to determine which regions are in-scope. At a minimum, you should include any region with an AWS resource (S3, RDS, EC2, etc).

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=1836199300)

## Control Description
GuardDuty is enabled for all in-scope regions.

## Required Evidence
* [all_detectors.json](./all_detectors.json) provides a list of detectors in a specific region.
  * This evidence is gathered by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/1.26.89/reference/services/guardduty/client/list_detectors.html) command in Boto 3.
* [DETECTOR_ID_config.json](./regions/us-east-1/DETECTOR_ID_config.json) provides information on the configuration of the specific detector.

## Testing Details
1. Review the [DETECTOR_ID_config.json](./regions/us-east-1/DETECTOR_ID_config.json) file and confirm the following:
    * Confirm the "Status" is enabled at the detector level.
    * Confirm the following "DataSources" were enabled: "CloudTrail", "DNSLogs", "FlowLogs", and "S3Logs".

## Support
- Please email us at info@auditops.io if you have any questions.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=253408408)

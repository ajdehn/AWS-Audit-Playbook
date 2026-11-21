## aws-cloudtrail-001 (multi-region cloudtrail)

### Test Overview

- **Test Description:** At least one multi-region CloudTrail trail has logging enabled.
- **Risk Level:** High
- **Risk Scenario:** CloudTrail is not properly configured across all regions, resulting in gaps in logging coverage. An attacker may perform actions in an unmonitored region without detection, limiting the organization’s ability to investigate security incidents and respond effectively.

### Test Procedures

1. Obtain a list of trails by calling the [`describe_trails()`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/describe_trails.html) Boto3 method.
2. Save the list of trails: [cloudtrail/trails.json](../../../evidence_library/aws/audit_evidence/cloudtrail/trails.json).  
3. Perform the following steps for each multi-region trail (`IsMultiRegionTrail` property is set to `true`):
    - Obtain the trail's logging status by calling the [`get_trail_status()`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/get_trail_status.html) Boto3 method.
    - Save the trail's logging status: [cloudtrail/trails/[trail_name]/trail_status.json](../../../evidence_library/aws/audit_evidence/cloudtrail/trails/example-trail/trail_status.json).
    - Inspect the trail's logging status to determine whether the `IsLogging` property is set to `true`.
4. This monitoring test is considered passing when **at least one** multi-region trail has logging enabled. If no such trail exists, note an exception.

 
### Remediation Guidance
1. Open the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/).
2. Navigate to **Trails** and select an existing trail or create a new trail.
3. Enable **Multi-region trail** to ensure events are recorded across all AWS regions.
4. Ensure **Enable log file validation** is selected to help verify the integrity of delivered log files.
5. Save the trail configuration and verify that logging is enabled.
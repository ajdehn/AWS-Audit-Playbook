## Control Description
At least one multi-region CloudTrail trail has logging enabled.

## Example Risk
CloudTrail is not properly configured across all regions, resulting in gaps in logging coverage. An attacker may perform actions in an unmonitored region without detection, limiting the organization’s ability to investigate security incidents and respond effectively.

## Test Procedures
1. Obtained a list of CloudTrail trails by calling the [describe_trails()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/describe_trails.html) boto3 command.  
2. Saved the list of CloudTrail trails: [CloudTrail/trails.json](/evidence_library/CloudTrail/trails.json).  
3. For each CloudTrail trail, inspected the trail configuration to determine whether `IsMultiRegionTrail` is set to `true`.  
4. For each multi-region trail, obtained the trail status by calling the [get_trail_status()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/get_trail_status.html) boto3 command.  
5. For each multi-region trail, saved the trail status: [CloudTrail/trails/[trail_name]/trail_status.json](/evidence_library/CloudTrail/trails/example-trail/trail_status.json).  
6. For each multi-region trail, inspected `trail_status.json` to determine whether `IsLogging` is set to `true`.  
7. Determined whether at least one CloudTrail trail has both `IsMultiRegionTrail = true` and `IsLogging = true`. If no such trail exists, an exception is noted.  

## Other Resources
- [Example Workpaper](/evidence_library/aws_audit_report.pdf)
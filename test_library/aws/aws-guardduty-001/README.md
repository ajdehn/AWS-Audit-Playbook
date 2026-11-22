## aws-guardduty-001 (guardduty enabled)

### Test Overview

- **Test Description:** Amazon GuardDuty is enabled in all in-scope AWS regions.
- **Risk Level:** High
- **Risk Scenario:** Malicious activity within your AWS account goes undetected because GuardDuty is not enabled in one or more regions, resulting in delayed detection and response to potential security incidents.

### Test Procedures

1. Perform the following for each in-scope region:
    - Obtain a list of GuardDuty detectors by calling the [list_detectors()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty/client/list_detectors.html) Boto3 method.
    - Save the list of GuardDuty detectors: [guardduty/[region]/detectors.json](../../../evidence_library/aws/audit_evidence/guardduty/us-east-1/detectors.json).
    - If no detectors are present in the JSON response, note an exception. No further testing required for this region.
2. Perform the following for each detector returned in all in-scope regions:
    - Obtain the detector's configuration by calling the [get_detector()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty/client/get_detector.html) Boto3 method.
    - Save the detector's configuration: [guardduty/[region]/[detector_id]/config.json](../../../evidence_library/aws/audit_evidence/guardduty/us-east-1/26c236aa2c9a6cae9e1992402db1010c/config.json).
    - Inspect the detector's configuration to determine whether the `Status` property is set to `ENABLED`.
3. This monitoring test is considered passing when **at least one** detector is enabled for each in-scope region. If a region, does not have an enabled detector, note an exception.

### Remediation Guidance

1. Open the [Amazon GuardDuty Console](https://console.aws.amazon.com/guardduty/).
2. Select the appropriate AWS region.
3. If GuardDuty is not enabled, select Get started to enable the service.
4. If a detector already exists, navigate to Settings and verify that the detector is enabled.
5. Repeat for each in-scope region.
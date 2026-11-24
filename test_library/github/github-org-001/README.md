## github-org-001 (org-wide MFA)

### Test Overview

- Test Description: GitHub organization settings require users to enable MFA.
- Risk Level: High
- Risk Scenario: A developer's GitHub password is compromised, allowing a malicious actor to view source code, exploit a vulnerability, and steal confidential data.

### Test Procedure
1. Obtain the GitHub organization metadata by calling the [Get an organization](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) GitHub endpoint.
2. Save the GitHub organization metadata: [orgs/org_settings.json](../../../evidence_library/github/audit_evidence/orgs/org_settings.json).
3. Inspect the GitHub organization metadata to determine whether the 'two_factor_requirement_enabled' property is set to 'true'.

### Remediation Guidance

#### Prerequisites:
The user performing this remediation must have “Owner” level access to the GitHub organization.

#### Warning:
Enabling this setting will block organization members from accessing repositories until they set up MFA, and it will automatically remove any outside collaborators or bot accounts that are not compliant.

#### Remediation Procedure:
1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Settings” > “Authentication security”.
3. Click the “ Require two-factor authentication for everyone” checkbox and click “Save”.
    - a. Note: We also recommend that you select the “Only allow secure two-factor methods” checkbox.
## github-org-003 (member public page creation)

### Test Overview

- Test Description: GitHub organization settings prevent members from creating public pages.
- Risk Level: Informational
- Risk Scenario: A developer accidentally creates a public page, temporarily exposing internal documentation to the public.

### Test Procedure

1. Call the [Get an organization endpoint](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) to obtain information about the GitHub organization.
2. Save the API response: orgs/org_settings.json ([example](../../../evidence_library/github/audit_evidence/orgs/org_settings.json)).
3. Inspect the evidence (orgs/org_settings.json) to determine whether the 'members_can_create_public_pages' property is set to 'false'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Member privileges” > “Pages creation”
3. Uncheck the “Public” checkbox and click “Save.
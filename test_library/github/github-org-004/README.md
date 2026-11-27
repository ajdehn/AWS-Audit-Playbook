## github-org-004 (member repo deletion)

### Test Overview

- Test Description: Organization members cannot delete or transfer repositories.
- Risk Level: Medium
- Risk Scenario: A developer accidentally creates a public page, temporarily exposing internal documentation to the public.

### Test Procedure

1. Obtain the GitHub organization metadata by calling the [Get an organization](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) GitHub endpoint.
2. Save the GitHub organization metadata: [orgs/org_settings.json](../../../evidence_library/github/audit_evidence/orgs/org_settings.json).
3. Inspect the GitHub organization metadata to determine whether the 'members_can_delete_repositories' property is set to 'false'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Member privileges” > “Repository deletion and transfer”
3. Uncheck the “Allow members to delete or transfer repositories for this organization” checkbox and click “Save.

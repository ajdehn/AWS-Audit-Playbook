## github-repo-001 (public repositories)

### Test Overview

- Test Description: Repositories in the GitHub organization are set to private.
- Risk Level: Informational
**Risk Scenario:** A GitHub repository is unintentionally configured as public, exposing source code to unauthorized individuals. An attacker discovers the exposed source code and uses it to identify vulnerabilities to gain unauthorized access to organizational resources.

### Test Procedure

1. Obtain a list of repositories by calling the [List organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) GitHub endpoint.
2. Save the list of repositories: orgs/repos.json ([example](../../../evidence_library/github/audit_evidence/orgs/repos.json)).
3. For each repository, inspect the 'private' property to determine whether the setting is set to 'true'.

### Remediation Guidance

#### Prerequisites:
The user performing this remediation must have “Owner” level access to the GitHub organization.

#### Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) > select your organization > navigate to the repository that needs to be updated to private.
2. Click the “Settings” tab in the top navigation menu.
3. On the “General” settings page, scroll all the way down to the “Danger Zone” section.
4. Locate “Change repository visibility” and click the “Change visibility” button.
5. Select “Change to private” from the dropdown menu.
6. Complete GitHub’s confirmation modals by clicking “I want to make this repository private” followed by “I have read and understand these effects”.
7. Enter the repository's requested safety verification and click “Make this repository private” to finalize the change.
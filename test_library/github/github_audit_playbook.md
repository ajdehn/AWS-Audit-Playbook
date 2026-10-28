## github-org-001 (org-wide MFA)

### Test Overview

- Test Description: GitHub organization settings require users to enable MFA.
- Risk Level: High
- Risk Scenario: A developer's GitHub password is compromised, allowing a malicious actor to view source code, exploit a vulnerability, and steal confidential data.

### Test Procedure

1. Call the [Get an organization endpoint](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) to obtain information about the GitHub organization.
2. Save the API response: orgs/org_settings.json.
3. Inspect the evidence (orgs/org_settings.json) to determine whether the 'two_factor_requirement_enabled' property is set to 'true'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Warning: Enabling this setting will block organization members from accessing repositories until they set up MFA, and it will automatically remove any outside collaborators or bot accounts that are not compliant.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Settings” > “Authentication security”.
3. Click the “ Require two-factor authentication for everyone” checkbox and click “Save”.
    - a. Note: We also recommend that you select the “Only allow secure two-factor methods” checkbox.

## github-org-002 (member public repository creation)

### Test Overview

- Test Description: GitHub organization settings prevent members from creating public repositories.
- Risk Level: Informational
- Risk Scenario: A developer accidentally creates a public repository, temporarily exposing proprietary source code to the public.

### Test Procedure

1. Call the [Get an organization endpoint](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) to obtain information about the GitHub organization.
2. Save the API response: orgs/org_settings.json.
3. Inspect the evidence (orgs/org_settings.json) to determine whether the 'members_can_create_public_repositories' property is set to 'false'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Member privileges” > “Repository creation”
3. Uncheck the “Public” checkbox and click “Save.
    - a. Note: As of 10/15/2026, this option is only configurable on the “Enterprise” GitHub plan.

## github-org-003 (member public page creation)

### Test Overview

- Test Description: GitHub organization settings prevent members from creating public pages.
- Risk Level: Informational
- Risk Scenario: A developer accidentally creates a public page, temporarily exposing internal documentation to the public.

### Test Procedure

1. Call the [Get an organization endpoint](https://docs.github.com/en/rest/orgs/orgs#get-an-organization) to obtain information about the GitHub organization.
2. Save the API response: orgs/org_settings.json.
3. Inspect the evidence (orgs/org_settings.json) to determine whether the 'members_can_create_public_pages' property is set to 'false'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) and select your organization.
2. Navigate to “Member privileges” > “Pages creation”
3. Uncheck the “Public” checkbox and click “Save.

## github-repo-001 (public repositories)

### Test Overview

- Test Description: Repositories in the GitHub organization are set to private.
- Risk Level: Informational

### Test Procedure

1. Call the [List organization repositories endpoint](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) to obtain a list of all repositories.
2. Save the API response: orgs/repos.json.
3. For each repository, inspect the 'private' property to determine whether the setting is set to 'true'.

### Remediation Guidance

Prerequisites: The user performing this remediation must have “Owner” level access to the GitHub organization.

Remediation Procedure:

1. [Open GitHub](https://github.com/settings/organizations) > select your organization > navigate to the repository that needs to be updated to private.
2. Click the “Settings” tab in the top navigation menu.
3. On the “General” settings page, scroll all the way down to the “Danger Zone” section.
4. Locate “Change repository visibility” and click the “Change visibility” button.
5. Select “Change to private” from the dropdown menu.
6. Complete GitHub’s confirmation modals by clicking “I want to make this repository private” followed by “I have read and understand these effects”.
7. Enter the repository's requested safety verification and click “Make this repository private” to finalize the change.

## github-repo-002 (pull request approvals)

### Test Overview

- Test Description: Repositories are configured to require an approval before a pull request is merged.
- Risk Level: High
- Risk Scenario: A developer bypasses branch protection requirements and introduces unreviewed, vulnerable, or malicious code into the application codebase.

### Test Procedure

1. Call the [List organization repositories endpoint](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) to obtain a list of all repositories.
2. Save the API response: orgs/repos.json.
3. For each repository, perform the following steps:
    - a. Call the [Get branch protection endpoint](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection) to obtain the classic branch protection configuration for the repository's default branch.
        - i. Note: This endpoint may return a 404 response if no classic branch protection configuration exists for the default branch. This does not necessarily indicate that the branch is unprotected, as repository or organization rulesets may also apply.
    - b. Save the API response: repos/[REPO_NAME]/branch_protection_rules.json.
    - c. Call the [List repository rulesets endpoint](https://docs.github.com/en/rest/repos/rules#list-repository-rulesets) to obtain the rulesets that apply to the repository.
        - i. Note: The includes_parents parameter defaults to true, so the response will include rulesets defined at the organization or enterprise level that apply to the repository.
    - d. Save the API response: repos/[REPO_NAME]/rulesets.json.
4. For each repository ruleset, perform the following steps:
    - a. Call the [Get a repository ruleset endpoint](https://docs.github.com/en/rest/repos/rules#get-repository-ruleset) to obtain the ruleset's configuration.
    - b. Save the API response: repos/[REPO_NAME]/rulesets/[RULE_ID].json.
5. For each repository, inspect the classic branch protection configuration and applicable rulesets to determine whether the default branch requires changes to be approved before a pull request can be merged.

### Remediation Guidance

Remediation Procedure:

1. Determine how you want to remediate this finding:
    - a. Recommended: Organization-wide ruleset (Step 2)
        - i. Note: This requires “Owner” level access to the GitHub organization.
    - b. Repository-level ruleset (Step 3) or branch protection rule (Step 4)
        - i. Note: Requires “Admin” level access to the repository.
2. Apply protection using an organization-wide ruleset:
    - a. [Open GitHub](https://github.com/settings/organizations) > select your organization > “Settings”.
    - b. In the left sidebar under the “Code, planning, and automation” section, click “Repository” and select “Rulesets”.
    - c. Click the “New ruleset” button and select “New branch ruleset” from the dropdown menu.
    - d. In the “Ruleset name” field, type a descriptive name (e.g., Global Default Branch Protection).
    - e. Set the “Enforcement status” to “Active”.
    - f. Scroll to the “Target repositories” section and configure the following:
        - i. Repository targeting criteria: Select “All repositories”, “Selected repositories…”, or configure filtering / matching.
    - g. Scroll to the “Target branches” section, click “Add target”, and select “Include default branch” or “Include all branches”.
    - h. Scroll down to the “Branch rules” section and check the box for “Require a pull request before merging”.
    - i. In the sub-options that appear, check the box for “Require approvals”.
    - j. Set the “Required approvals” field to your organization's preferred minimum threshold (typically 1 or 2).
    - k. Scroll to the bottom of the page and click “Create” to activate the rule organization-wide.
3. Apply a ruleset to the GitHub repository:
    - a. Navigate to the repository to be updated > click “Settings” in the top navigation menu.
    - b. In the left sidebar, locate the “Code, planning and automation” section and click “Rulesets”.
    - c. Click the “New rulesets” button in the top right and select “New branch rulesets” from the dropdown menu.
    - d. In the “Ruleset name” field, enter a descriptive name (e.g., Protect Default Branch).
    - e. Set the “Enforcement status” to “Active”.
    - f. Scroll down to the “Target branches” section, click “Add target”, and select “Include default branch” or “Include all branches”.
    - g. Scroll down to the “Branch rules” section and check the box for “Require a pull request before merging”.
    - h. In the sub-options that appear, check the box for “Require approvals”.
    - i. Set the “Required approvals” field to your organization's preferred minimum threshold (typically 1 or 2).
    - j. Scroll to the bottom of the page and click “Create” to enforce the ruleset.
4. Apply a branch protection rule to the GitHub repository:
    - a. Navigate to the repository to be updated > click “Settings” in the top navigation menu.
    - b. In the left sidebar, locate the “Code, planning and automation” section and click “Branches”.
    - c. Under the Branch protection rules section, click the “Add classic branch protection rule” button (or click “Edit” next to an existing rule targeting your default branch).
    - d. In the “Branch name pattern” field, type the name of the branch you want to protect (e.g., main or master).
    - e. In the Protect matching branches checklist, check the box for “Require a pull request before merging”.
    - f. Check the nested box for “Require approvals”.
    - g. Set the “Required approving reviews” dropdown to your organization's preferred minimum threshold (typically 1 or 2).
    - h. Scroll to the bottom of the page and click “Create” (or “Save changes”) to enforce the rule.

## github-repo-003 (admin branch protection)

### Test Overview

- Test Description: Repositories are configured so that administrators are subject to branch protection requirements.
- Risk Level: High
- Risk Scenario: A repository administrator bypasses branch protection requirements and introduces unreviewed, vulnerable, or malicious code into the application codebase.

### Test Procedure

1. Call the [List organization repositories endpoint](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) to obtain a list of all repositories.
2. Save the API response: orgs/repos.json.
3. For each repository, perform the following steps:
    - a. Call the [Get branch protection endpoint](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection) to obtain the classic branch protection configuration for the repository's default branch.
    - b. Save the API response: repos/[REPO_NAME]/branch_protection_rules.json.
    - c. Call the [List repository rulesets endpoint](https://docs.github.com/en/rest/repos/rules#list-repository-rulesets) to obtain the rulesets that apply to the repository.
        - i. Note: The includes_parents parameter defaults to true, so the response may include rulesets defined at the organization or enterprise level that apply to the repository.
    - d. Save the API response: repos/[REPO_NAME]/rulesets.json.
4. For each repository ruleset, perform the following steps:
    - a. Call the [Get a repository ruleset endpoint](https://docs.github.com/en/rest/repos/rules#get-repository-ruleset) to obtain the ruleset's configuration.
    - b. Save the API response: repos/[REPO_NAME]/rulesets/[RULE_ID].json.
5. For each repository, inspected the branch protection rules and ruleset(s) to determine whether Administrators are subject to branch protection rules / ruleset requirements.

### Remediation Guidance

Remediation Procedure:

1. Determine which protection mechanism is appropriate:
    - a. Recommended: Organization-wide ruleset (Step 2)
        - i. Note: This requires “Owner” level access to the GitHub organization.
    - b. Repository-level ruleset (Step 3) or branch protection rule (Step 4)
        - i. Note: Requires “Admin” level access to the repository.
2. Apply an organization-wide ruleset:
    - a. [Open GitHub](https://github.com/settings/organizations) > select your organization > “Settings”.
    - b. Under Code, planning, and automation, select Repository and then Rulesets.
    - c. Create a new branch ruleset or edit an existing one.
    - d. Set Enforcement status to Active.
    - e. Scroll to the “Target repositories” section and configure the following:
        - i. Repository targeting criteria: Select “All repositories”, “Selected repositories…”, or configure filtering / matching.
    - f. Scroll to the “Target branches” section, click “Add target”, and select “Include default branch” or “Include all branches”.
    - g. Scroll down to the “Branch rules” section and check the box for “Require a pull request before merging”.
    - h. In the sub-options that appear, check the box for “Require approvals”.
    - i. Set the “Required approvals” field to your organization's preferred minimum threshold (typically 1 or 2).
    - j. Review the bypass list and remove administrator bypass permissions that conflict with the intended control. Check for applicable organization-administrator bypass permissions as well as repository-role administrator bypass permissions.
    - k. Scroll to the bottom of the page and click “Create” to activate the rule organization-wide.
3. Apply a ruleset to the GitHub repository:
    - a. Open the repository and select Settings.
    - b. Under Code, planning, and automation, select Rulesets.
    - c. Create a new branch ruleset or edit an existing one.
    - d. Set Enforcement status to Active.
    - e. Configure the target branches to include the default branch.
    - f. Configure the required branch protections.
    - g. Review the bypass list and remove administrator bypass permissions that conflict with the intended control.
    - h. Save the ruleset.
4. Apply a branch protection rule to a GitHub repository:
    - a. Open the repository and select Settings.
    - b. Under Code, planning, and automation, select Branches.
    - c. Create or edit the branch protection rule matching the default branch.
    - d. Enable Include administrators, or the equivalent administrator-enforcement setting displayed by GitHub.
    - e. Configure the required branch protections.
    - f. Save the changes.
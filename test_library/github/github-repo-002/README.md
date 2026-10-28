## github-repo-002 (pull request approvals)

### Test Overview

- Test Description: Repositories are configured to require an approval before a pull request is merged.
- Risk Level: High
- Risk Scenario: A developer bypasses branch protection requirements and introduces unreviewed, vulnerable, or malicious code into the application codebase.

### Test Procedure

1. Call the [List organization repositories endpoint](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) to obtain a list of all repositories.
2. Save the API response: ([example](../../../evidence_library/github/audit_evidence/orgs/repos.json)).
3. For each repository, perform the following steps:
    - a. Call the [Get branch protection endpoint](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection) to obtain the classic branch protection configuration for the repository's default branch.
        - i. Note: This endpoint may return a 404 response if no classic branch protection configuration exists for the default branch. This does not necessarily indicate that the branch is unprotected, as repository or organization rulesets may also apply.
    - b. Save the API response: repos/[REPO_NAME]/branch_protection_rules.json ([example](../../../evidence_library/github/audit_evidence/repos/compliant-repo/branch_protection_rules.json)).
    - c. Call the [List repository rulesets endpoint](https://docs.github.com/en/rest/repos/rules#list-repository-rulesets) to obtain the rulesets that apply to the repository.
        - i. Note: The includes_parents parameter defaults to true, so the response will include rulesets defined at the organization or enterprise level that apply to the repository.
    - d. Save the API response: repos/[REPO_NAME]/rulesets.json ([example](../../../evidence_library/github/audit_evidence/repos/compliant-repo/rulesets.json)).
4. For each repository ruleset, perform the following steps:
    - a. Call the [Get a repository ruleset endpoint](https://docs.github.com/en/rest/repos/rules#get-repository-ruleset) to obtain the ruleset's configuration.
    - b. Save the API response: repos/[REPO_NAME]/rulesets/[RULE_ID].json ([example](../../../evidence_library/github/audit_evidence/repos/compliant-repo/rulesets/19733163.json)).
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
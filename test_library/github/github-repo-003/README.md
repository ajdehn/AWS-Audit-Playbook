## github-repo-003 (admin branch protection)

### Test Overview

- Test Description: Repositories are configured so that administrators are subject to branch protection requirements.
- Risk Level: High
- Risk Scenario: A repository administrator bypasses branch protection requirements and introduces unreviewed, vulnerable, or malicious code into the application codebase.

### Test Procedure

1. Call the [List organization repositories endpoint](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) to obtain a list of all repositories.
2. Save the API response: ([example](../../../evidence_library/github/audit_evidence/orgs/repos.json)).
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
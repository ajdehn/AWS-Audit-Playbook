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

#### Determine which protection mechanism is appropriate:
- **Option 1:** Apply Organization-wide ruleset
    - Note: This requires “Owner” level access to the GitHub organization.
- **Option 2:** Apply a Repository-level ruleset
    - Note: Requires “Admin” level access to the repository.
- **Option 3:** Apply a branch protection rule (Option 3)
    - Note: Requires “Admin” level access to the repository.

#### Option 1: Apply an organization-wide ruleset:
1. [Open GitHub](https://github.com/settings/organizations) > select your organization > “Settings”.
2. Under Code, planning, and automation, select Repository and then Rulesets.
3. Create a new branch ruleset or edit an existing one.
4. Set Enforcement status to Active.
5. Scroll to the “Target repositories” section and configure the following:
   - Repository targeting criteria: Select “All repositories”, “Selected repositories…”, or configure filtering / matching.
6. Scroll to the “Target branches” section, click “Add target”, and select “Include default branch” or “Include all branches”.
7. Scroll down to the “Branch rules” section and check the box for “Require a pull request before merging”.
8. In the sub-options that appear, check the box for “Require approvals”.
9. Set the “Required approvals” field to your organization's preferred minimum threshold (typically 1 or 2).
10. Review the bypass list and remove administrator bypass permissions that conflict with the intended control. Check for applicable organization-administrator bypass permissions as well as repository-role administrator bypass permissions.
11. Scroll to the bottom of the page and click “Create” to activate the rule organization-wide.

#### Option 2: Apply an organization-wide ruleset:
1. Open GitHub and select your organization.
2. Under Code, planning, and automation, select Repository and then Rulesets.
3. Create a new branch ruleset or edit an existing one.
4. Set Enforcement status to Active.
5. Configure the target branches to include the default branch.
6. Configure the required branch protections.
7. Review the bypass list and remove administrator bypass permissions that conflict with the intended control.
8. Click “Save changes” to apply the ruleset.

#### Option 3: Apply a branch protection rule to a GitHub repository:
1. Open the repository and select Settings.
2. Under Code, planning, and automation, select Branches.
3. Create or edit a branch protection rule matching the default branch.
4. Enable “Include administrators”, or the equivalent administrator-enforcement setting displayed by GitHub.
5. Configure the required branch protections.
6. Click “Save changes” to apply the rule.

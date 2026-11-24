## github-repo-004 (required status checks)

### Test Overview

- **Test Description:** Active repositories require at least one status check to pass before changes can be merged.
- **Risk Level:** High
- **Risk Scenario:** A developer accidentally introduces a bug or security vulnerability into your production code. Because no status checks are required, the changes are merged without automated testing. Your customers are now experiencing downtime, and your engineering team is spending the weekend trying to figure out what went wrong.

### Test Procedures

1. Obtain a list of repositories by calling the [List organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories) GitHub endpoint.
2. Save the list of repositories: [orgs/repos.json](../../../evidence_library/github/audit_evidence/orgs/repos.json).
3. Perform the following for each repository:
   - Check whether the repository is archived. Exclude archived repositories from status check testing because they are not actively maintained.
   - Obtain the classic branch protection configuration for the repository's default branch by calling the [Get branch protection](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection) GitHub endpoint.
   - Save the API response: [repos/[REPO_NAME]/branch_protection_rules.json](../../../evidence_library/github/audit_evidence/repos/REPO_NAME/branch_protection_rules.json).
   - Obtain the repository's rulesets by calling the [List repository rulesets](https://docs.github.com/en/rest/repos/rules#list-repository-rulesets) GitHub endpoint.
   - Save the API response: [repos/[REPO_NAME]/rulesets.json](../../../evidence_library/github/audit_evidence/repos/REPO_NAME/rulesets.json).
4. Perform the following for each repository ruleset:
   - Obtain the ruleset configuration by calling the [Get repository ruleset](https://docs.github.com/en/rest/repos/rules#get-repository-ruleset) GitHub endpoint.
   - Save the API response: [repos/[REPO_NAME]/rulesets/[RULE_ID].json](../../../evidence_library/github/audit_evidence/repos/REPO_NAME/rulesets/RULE_ID.json).
5. For each active repository, inspect the classic branch protection configuration and applicable rulesets to determine whether the default branch requires at least one status check to pass before changes can be merged.

### Remediation Guidance

**Prerequisites:**

The user performing this remediation must have administrator access or sufficient repository permissions to modify branch protection rules or repository rulesets.

**Remediation Procedure:**

GitHub supports two methods for requiring status checks before changes can be merged: classic branch protection rules and repository rulesets. Follow the appropriate procedure based on the repository's existing configuration.

**Option 1: Classic Branch Protection Rules**

1. [Open GitHub](https://github.com/settings/organizations), select your organization, and navigate to the repository that needs to be updated.
2. Click the **Settings** tab in the top navigation menu.
3. Navigate to **Branches** under **Code, planning, and automation**.
4. Under **Branch protection rules**, locate the rule protecting the repository's default branch and click **Edit**.
5. Locate the **Require status checks to pass before merging** setting and enable it.
6. Search for and select at least one appropriate status check to require before changes can be merged.
7. Optionally, enable **Require branches to be up to date before merging** to ensure that status checks run against the latest version of the default branch.
8. Save the changes.
9. Verify that the default branch requires at least one status check to pass before changes can be merged.

**Option 2: Repository Rulesets**

1. [Open GitHub](https://github.com/settings/organizations), select your organization, and navigate to the repository that needs to be updated.
2. Click the **Settings** tab in the top navigation menu.
3. Navigate to **Rules** > **Rulesets**.
4. Select an existing ruleset that targets the repository's default branch or create a new ruleset.
5. Under **Target branches**, verify that the repository's default branch is included.
6. Under **Branch protections**, enable **Require status checks to pass**.
7. Under **Additional settings**, add at least one appropriate status check to require before changes can be merged.
8. Optionally, enable **Require branches to be up to date before merging**.
9. Verify that the ruleset is set to **Active** and save the changes.
10. Verify that the default branch requires at least one status check to pass before changes can be merged.

Repeat for each active repository that does not require at least one status check before changes can be merged.
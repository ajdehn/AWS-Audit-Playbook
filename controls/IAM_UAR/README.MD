## Control Description
Management conducts a user access review on at least a quarterly basis.

## Example Risk
A disgruntled former employee realizes they still have access to your organization's AWS account. In a fit of rage, they download local copies of your production database and delete the DB along with all your backups. They are demanding $1,000,000 in order for you to get your data back.

## Required Evidence
* [all_iam_users.json](/evidence_library/IAM/all_iam_users.json) lists all IAM users in the AWS account.
  * This evidence is gathered by calling the [list_users()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_users.html) command in Boto3.
* For each IAM user, we need the following evidence:
  * [attached_managed_policies.json](/evidence_library/IAM/users/audit-user/attached_managed_policies.json) lists all IAM policies attached to an IAM user. This evidence is gathered by calling the [list_attached_user_policies()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_attached_user_policies.html) command in Boto3.
  * [inline_policies.json](/evidence_library/IAM/users/maverick/inline_policies.json) lists all inline policies granted to the IAM user. This evidence is gathered by calling the [list_user_policies()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_user_policies.html) command in Boto3.
  * [group_membership.json](/evidence_library/IAM/users/goose/group_membership.json) lists all groups the IAM user is a part of. This evidence is gathered by calling the [list_groups_for_user()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_groups_for_user.html) command in Boto3.
* For each IAM group, we need the following evidence:
  * [attached_managed_policies.json](/evidence_library/IAM/groups/Student-Group/attached_managed_policies.json) lists all IAM policies attached to the IAM group. This evidence is gathered by calling the [list_attached_group_policies()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_attached_group_policies.html) command in Boto3.
  * [inline_policies.json](/evidence_library/IAM/groups/Student-Group/inline_policies.json) lists all inline policies granted to the IAM group. This evidence is gathered by calling the [list_groups_for_user()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_groups_for_user.html) command in Boto3.

## Testing Details
1. Review management's most recent AWS user access review and confirm they have conducted a full review of the permission structure. At a minimum, the review should consider permissions attached to IAM users (inline and attached), IAM group membership, and permissions (inline & attached) granted to each group.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=2005756602)
- [Example User Access Review](https://docs.google.com/spreadsheets/d/1epwxTlQ885XFQvFFiRAXecGDwrd8W_poTtay5_4ApAA/edit?usp=sharing)

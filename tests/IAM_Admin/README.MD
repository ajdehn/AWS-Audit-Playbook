## Control Description
AWS administrative access is appropriately restricted.

## Required Evidence
* [administrative_entities.json](/evidence_library/IAM/administrative_entities.json) lists all groups, roles, and users attached to the AWS administrative access policy.
  * This evidence is gathered by calling the [list_entitities_for_policy()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_entities_for_policy.html) command in Boto3.
* [admin_group_members.json](/evidence_library/IAM/admin_group_members.json) lists all group members for a specific group.
  * This evidence is gathered by calling the [get_group()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_group.html) command in Boto3. NOTE: This command will need to be run for each group with adminsitrative access.

## Testing Details
1. Open the [administrative_entities.json](/evidence_library/IAM/administrative_entities.json) and confirm that all entities (groups, roles, and users) require administrative access.

## Other Resources
- [Example Workpaper](https://docs.google.com/spreadsheets/d/1bGfbXUTSzVCSGCWn7UtG6QN4wWeEKdrubygcCuDDjbI/edit?gid=2005756602)

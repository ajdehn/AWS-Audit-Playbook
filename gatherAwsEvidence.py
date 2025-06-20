import boto3
import json
import os
import time
from botocore.exceptions import ClientError

def main():
    # Save a list of all in-scope regions (including opt-in regions)
    regionList = boto3.client('account').list_regions(RegionOptStatusContains=['ENABLED','ENABLED_BY_DEFAULT'])
    saveJson(regionList, f'audit_evidence/region_list.json')

    inScopeRegions = []
    for region in regionList['Regions']:
        inScopeRegions.append(region['RegionName'])

    print('Gathering GuardDuty evidence')
    for region in inScopeRegions:
        guardduty_client = boto3.client('guardduty', region_name=region)
        allDetectors = fetchData(guardduty_client.list_detectors)
        saveJson(allDetectors, f'audit_evidence/GuardDuty/regions/{region}/all_detectors.json')
        for detector_id in allDetectors['DetectorIds']:
            detectorDetails = guardduty_client.get_detector(DetectorId=detector_id)
            saveJson(detectorDetails, f'audit_evidence/GuardDuty/regions/{region}/{detector_id}_config.json')
            # Filter criteria for only active GuardDuty findings
            active_findings_filter = {
                'Criterion': {
                    'service.archived': {
                        'Eq': ['false']
                    }
                }
            }
            findingsBySeverity = guardduty_client.get_findings_statistics(DetectorId=detector_id, 
            FindingStatisticTypes=['COUNT_BY_SEVERITY'], FindingCriteria=active_findings_filter)
            saveJson(findingsBySeverity, f'audit_evidence/GuardDuty/regions/{region}/{detector_id}_findings_stats.json')
            
            findings = []

            # Step 1: List only ACTIVE finding IDs using filter
            paginator = guardduty_client.get_paginator('list_findings')
            page_iterator = paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'service.archived': {
                            'Eq': ['false']
                        }
                    }
                }
            )

            all_finding_ids = []
            for page in page_iterator:
                all_finding_ids.extend(page['FindingIds'])

            # Step 2: Get details in batches
            for i in range(0, len(all_finding_ids), 50):
                batch_ids = all_finding_ids[i:i + 50]
                response = guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=batch_ids
                )
                findings.extend(response['Findings'])

            # Step 3: Sort by severity descending
            findings.sort(key=lambda x: x['Severity'], reverse=True)
            saveJson(findings, f'audit_evidence/GuardDuty/regions/{region}/{detector_id}_findings.json')

    print('Gathering EventBridge evidence') # Used in "GD_Alerts"
    for region in inScopeRegions:
        eventbridge_client = boto3.client('events', region_name=region)
        sns_client = boto3.client('sns', region_name=region)
        allEventBridgeRules = fetchData(eventbridge_client.list_rules)
        saveJson(allEventBridgeRules, f"audit_evidence/EventBridge/{region}/allEventBridgeRules.json")
        for rule in allEventBridgeRules['Rules']:
            if rule.get('EventPattern'):
                if 'aws.guardduty' in json.loads(rule['EventPattern'])['source'] and rule.get('State') == 'ENABLED':
                    ruleName = rule['Name']
                    targets = eventbridge_client.list_targets_by_rule(Rule=rule['Name'])
                    saveJson(targets, f"audit_evidence/EventBridge/{region}/{ruleName}_targets.json")
                    for target in targets['Targets']:
                        if "sns" in target['Arn']:
                            topicSubscriptions = sns_client.list_subscriptions_by_topic(TopicArn=target['Arn'])
                            topicName = target['Arn'].split(':')[5]
                            saveJson(topicSubscriptions, f"audit_evidence/SNS/{region}/{topicName}.json")

    # Gather evidence for IAM
    print('Gathering IAM evidence')
    iam_client = boto3.client('iam')
    # Generate credentials report & save to JSON (used for IAM_MFA test).
    iam_client.generate_credential_report()
    time.sleep(5)
    credentialReport = iam_client.get_credential_report()
    saveJson(credentialReport, 'audit_evidence/IAM/credentials_report.json')
    # Save credentials report as a CSV
    decodedCredentialReport = credentialReport['Content'].decode("utf-8")
    with open("audit_evidence/IAM/credentials_report.csv", "w") as file:
        file.write(decodedCredentialReport)
        
    # Gather evidence for IAM_Admin
    administrativeEntities = iam_client.list_entities_for_policy(
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    saveJson(administrativeEntities, 'audit_evidence/IAM/administrative_entities.json')

    for group in administrativeEntities['PolicyGroups']:
        groupMembers = iam_client.get_group(
            GroupName=group['GroupName']
        )
        saveJson(groupMembers, f'audit_evidence/IAM/groups/{group['GroupName']}_members.json')

    # Gather evidence for IAM_PWD
    try:
        passwordPolicy = iam_client.get_account_password_policy()
        saveJson(passwordPolicy, 'audit_evidence/IAM/password_policy.json')
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print("WARNING: IAM Password Policy has not been set.")
        else:
            raise

    # Gather evidence for S3.
    print('Gathering S3 evidence')
    s3_client = boto3.client('s3')
    # Get all S3 buckets
    allBuckets = s3_client.list_buckets()
    saveJson(allBuckets, 'audit_evidence/S3/all_s3_buckets.json')
    # Save necessary evidence for each bucket.
    for bucket in allBuckets['Buckets']:
        bucketName = bucket['Name']
        # Collect & save encryption evidence
        # TODO: Add error handling
        bucketEncryption = s3_client.get_bucket_encryption(Bucket=bucketName)
        saveJson(bucketEncryption, f"audit_evidence/S3/buckets/{bucketName}/encryption_settings.json")
        # TODO: Add error handling
        # TODO: Get global S3 block settings
        # Collect & save public access settings
        publicBucketSettings = s3_client.get_public_access_block(Bucket=bucketName)
        saveJson(publicBucketSettings, f"audit_evidence/S3/buckets/{bucketName}/public_access_settings.json")
        # Collect & save bucket tags
        try:
            bucketTags = s3_client.get_bucket_tagging(Bucket=bucketName) 
            saveJson(bucketTags, f"audit_evidence/S3/buckets/{bucket['Name']}/bucket_tags.json")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchTagSet':
                print(f"Warning: {bucket['Name']} does not have tags.")
                pass
            else:
                raise

    print('Gathering EC2 & EBS evidence')
    for region in inScopeRegions:
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            allVolumes = fetchData(ec2_client.describe_volumes)
            saveJson(allVolumes, f'audit_evidence/EC2/regions/{region}/allVolumes.json')
            allInstances = fetchData(ec2_client.describe_volumes)
            saveJson(allInstances, f'audit_evidence/EC2/regions/{region}/allInstances.json')         
        except Exception as e:
            print("Exception in region: ", region)
            if 'InvalidClientTokenId' in e.response['Error']['Code']:
                # NOTE: Error handling for opt-in only regions (ex. af-south-1).
                # If this error occurs, this region is not utilized doesn't utilize this region.
                pass
            else:
                raise            

    print('Gathering RDS evidence')
    for region in inScopeRegions:
        try:
            rds_client = boto3.client('rds', region_name=region)
            allDatabases = fetchData(rds_client.describe_db_instances)
            saveJson(allDatabases, f'audit_evidence/RDS/regions/{region}.json')
        except Exception as e:
            print("Exception in region: ", region)
            if 'InvalidClientTokenId' in e.response['Error']['Code']:
                # NOTE: Error handling for opt-in only regions (ex. af-south-1).
                # If this error occurs, this region is not utilized doesn't utilize this region.
                pass
            else:
                raise
    
    print('Gathering CloudTrail evidence')
    cld_trail_client = boto3.client('cloudtrail')
    allTrails = cld_trail_client.describe_trails(includeShadowTrails=True)
    saveJson(allTrails, 'audit_evidence/CloudTrail/all_trails.json')

"""
    Saves a json file to a specified path
"""
def saveJson(extract, filePath):
    # isolating out the directory path to the file and creating the directory
    brokenUpPath = filePath.split('/')
    dirPathToFile = '/'.join(brokenUpPath[:len(brokenUpPath) - 1]) 
    createPath(dirPathToFile)
    
    with open(filePath, 'w') as f:
        json.dump(extract, f, indent=4, default=str)
    f.close()

"""
    Create path if it does not exist.
"""
def createPath(path):
    isExist = os.path.exists(path)
    if not isExist:
        os.makedirs(path)

# NOTE: kwargs means keyword argument for variable number wanted...
# https://www.geeksforgeeks.org/args-kwargs-python/#:~:text=The%20special%20syntax%20*args%20in,used%20with%20the%20word%20args.
# T
"""
    This function interacts with the AWS objects in the repeatable
    fashion that they've outlined.
    It will retrieve next results using the marker for paginated results.
    The first argument is the function that should be executed,
    the second param is the name of the marker, and the last argument is any
    key word argument that should be passed
"""
def fetchData(clientFn, markerName='Marker', **kwargs):
    result = clientFn(**kwargs)
    isTruncated = ('IsTruncated' in result and result['IsTruncated']) or markerName in result
    while isTruncated:
        # the | operator has duplicate keys overwritten by results on the
        # right while all unique data is joined
        markerOrPaginationDict = {markerName: result[markerName]}
        newResult = clientFn(**kwargs, **markerOrPaginationDict)
        result = combineDicts(result, newResult)
        isTruncated = ('IsTruncated' in result and result['IsTruncated'])  or markerName in newResult
        print(f'The data from {clientFn.__name__} is truncated!')
    return result

"""
    combines dicts with modified behavior of 1 level deep lists to append instead of overwrite. 
    Otherwise dict2 will overwrite dict1
"""
def combineDicts(dict1, dict2):
    for k,v in dict2.items():
        if k in dict1 and type(dict1[k]) == type([]) and type([]) == type(v):
            for item in v:
                dict1[k].append(item)
        else:
            dict1[k] = v
    return dict1

if __name__ == '__main__':
    main()
import boto3
import json
import os
import time
from botocore.exceptions import ClientError

def main():
    # TODO: Update the in-scope regions (Ex. "inScopeRegions":['us-east-1','us-east-2']). If left empty, all regions will be included.
    # TODO: Mark controls as 'False' if they are not in-scope for the audit. This will ensure you only save the necessary evidence.
    # You can find all controls here: https://github.com/ajdehn/AWS-Audit-Playbook/tree/main/controls
    config = {
        "inScopeRegions": [],
        "Cloud_Trail_Multi_Region": True,
        "EBS_Encryption": True,
        "EC2_Public_Security_Groups": True,
        "EC2_Tags": True,
        "GD_Alerts": True,
        "GD_Enabled": True,
        "GD_Findings": True,
        "IAM_Admin": True,  
        "IAM_Key_Age": True,
        "IAM_MFA": True,
        "IAM_PWD": True,
        "RDS_Backup": True,
        "RDS_Encrypt": True,
        "RDS_Public": True,
        "RDS_Tags": True,     
        "S3_Encrypt": True,
        "S3_Public": True,
        "S3_Tags": True
    }

    config = checkConfigFile(config)
    saveIAMEvidence(config)
    saveS3Evidence(config)
    saveGuardDutyEvidence(config)
    saveEC2Evidence(config) # NOTE: This saves evidence for both EC2 & EBS
    saveRDSEvidence(config)
    saveEventBridgeEvidence(config)
    saveCloudTrailEvidence(config)

"""
    Check if config file is valid. Raises an error if the config file is misconfigured.
"""
def checkConfigFile(config):
    # Convert inScopeRegions to lowercase.
    config['inScopeRegions'] = [region.lower() for region in config['inScopeRegions']]

    # Create a list of all active AWS regions.
    regionList = boto3.client('account').list_regions(RegionOptStatusContains=['ENABLED','ENABLED_BY_DEFAULT'])
    awsRegionList = []
    for region in regionList['Regions']:
        awsRegionList.append(region['RegionName'])

    # Check if regions listed in scope are actually in AWS.
    for region in config['inScopeRegions']:
        if region not in awsRegionList:
            raise ValueError(f"{region} is not a valid region. Please update the config file.")
    
        # Check if each control is in the config file, and confirm that the value is boolean.
    allControls = ['Cloud_Trail_Multi_Region', 'EBS_Encryption', 'EC2_Public_Security_Groups', 'EC2_Tags',
                   'GD_Alerts', 'GD_Enabled', 'GD_Findings', 'IAM_Admin', 'IAM_Key_Age', 'IAM_MFA', 'IAM_PWD',
                   'RDS_Backup', 'RDS_Encrypt', 'RDS_Public', 'RDS_Tags', 'S3_Encrypt', 'S3_Public', 'S3_Tags']
    for controlName in allControls:
        inScopeControl = config.get(controlName)
        if inScopeControl is None:
            raise KeyError(f"Invalid configuration. {controlName} is not in the config file")
        if not isinstance(config[controlName], bool):
            raise ValueError(f"Invalid configuration. {controlName} should be True or False")

    saveJson(config, f'audit_evidence/audit_scope.json')

    # If regions list is empty, make all regions in scope.
    if len(config['inScopeRegions']) == 0:
        config['inScopeRegions'] = awsRegionList

    return config


"""
    Save all IAM related evidence
"""
def saveIAMEvidence(config):
    print('Gathering IAM evidence')
    iam_client = boto3.client('iam')

    if config['IAM_MFA'] or config['IAM_Key_Age']:
        # Generate credentials report & save to JSON.
        iam_client.generate_credential_report()
        time.sleep(5)
        credentialReport = iam_client.get_credential_report()
        saveJson(credentialReport, 'audit_evidence/IAM/credentials_report.json')
        # Save credentials report as a CSV
        decodedCredentialReport = credentialReport['Content'].decode("utf-8")
        with open("audit_evidence/IAM/credentials_report.csv", "w") as file:
            file.write(decodedCredentialReport)

    if config['IAM_Admin']:
        administrativeEntities = iam_client.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        saveJson(administrativeEntities, 'audit_evidence/IAM/administrative_entities.json')

        for group in administrativeEntities['PolicyGroups']:
            groupMembers = iam_client.get_group(
                GroupName=group['GroupName']
            )
            saveJson(groupMembers, f'audit_evidence/IAM/groups/{group['GroupName']}_members.json')

    if config['IAM_PWD']:
        try:
            passwordPolicy = iam_client.get_account_password_policy()
            saveJson(passwordPolicy, 'audit_evidence/IAM/password_policy.json')
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                print("WARNING: IAM Password Policy has not been set.")
            else:
                raise


def saveEC2Evidence(config):
    if not any ([config['EBS_Encryption'], config['EC2_Tags'], config['EC2_Public_Security_Groups']]):
        # No S3 tests are in-scope.
        return
    print('Gathering EC2 & EBS evidence')
    for region in config['inScopeRegions']:
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            if config['EBS_Encryption']:
                allVolumes = fetchData(ec2_client.describe_volumes)
                saveJson(allVolumes, f'audit_evidence/EC2/regions/{region}/allVolumes.json')
            if config['EC2_Tags']:
                allInstances = fetchData(ec2_client.describe_volumes)
                saveJson(allInstances, f'audit_evidence/EC2/regions/{region}/allInstances.json')
            if config['EC2_Public_Security_Groups']:
                allSecurityGroups = fetchData(ec2_client.describe_security_groups)
                saveJson(allSecurityGroups, f'audit_evidence/EC2/regions/{region}/allSecurityGroups.json')
        except Exception as e:
            print("Exception in region: ", region)
            if 'InvalidClientTokenId' in e.response['Error']['Code']:
                # NOTE: Error handling for opt-in only regions (ex. af-south-1).
                # If this error occurs, this region is not utilized doesn't utilize this region.
                pass
            else:
                raise   


def saveS3Evidence(config):
    if not any ([config['S3_Encrypt'], config['S3_Public'], config['S3_Tags']]):
        # No S3 tests are in-scope.
        return
    print('Gathering S3 evidence')
    s3_client = boto3.client('s3')
    # Get all S3 buckets
    allBuckets = s3_client.list_buckets()
    saveJson(allBuckets, 'audit_evidence/S3/all_s3_buckets.json')
    # Save necessary evidence for each bucket.
    for bucket in allBuckets['Buckets']:
        bucketName = bucket['Name']
        # TODO: Improve error handling
        if config['S3_Encrypt']:
            # Collect & save encryption evidence
            try:
                bucketEncryption = s3_client.get_bucket_encryption(Bucket=bucketName)
                saveJson(bucketEncryption, f"audit_evidence/S3/buckets/{bucketName}/encryption_settings.json")
            except ClientError as e:
                print(f"Warning: unable to collect S3 encryption settings for {bucket['Name']}.")
                pass
        if config['S3_Public']:
            # Collect & save public access settings        
            try:
                publicBucketSettings = s3_client.get_public_access_block(Bucket=bucketName)
                saveJson(publicBucketSettings, f"audit_evidence/S3/buckets/{bucketName}/public_access_settings.json")
            except ClientError as e:
                print(f"Warning: unable to collect S3 public access settings for {bucket['Name']}.")
                pass
        if config['S3_Tags']:   
            # Collect & save bucket tags
            try:
                bucketTags = s3_client.get_bucket_tagging(Bucket=bucketName) 
                saveJson(bucketTags, f"audit_evidence/S3/buckets/{bucket['Name']}/bucket_tags.json")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchTagSet':
                    print(f"Warning: {bucket['Name']} does not have tags.")
                    pass
                else:
                    print(f"Warning: unable to collect S3 tags for {bucket['Name']}.")
                    pass

def saveRDSEvidence(config):
    if not any ([config['RDS_Encrypt'], config['RDS_Public'], config['RDS_Tags']]):
        # No RDS tests are in-scope.
        return    
    print('Gathering RDS evidence')
    for region in config['inScopeRegions']:
        try:
            rds_client = boto3.client('rds', region_name=region)
            allDatabases = fetchData(rds_client.describe_db_instances)
            saveJson(allDatabases, f'audit_evidence/RDS/regions/{region}.json')
        except Exception as e:
            print("Exception in region: ", region)
            if 'InvalidClientTokenId' in e.response['Error']['Code']:
                # NOTE: Error handling for opt-in only regions (ex. af-south-1).
                # If this error occurs, this region is not utilized.
                pass
            else:
                raise

def saveGuardDutyEvidence(config):
    if not any ([config['GD_Alerts'], config['GD_Enabled'], config['GD_Findings']]):
        # No GuardDuty tests are in-scope.
        return
    print('Gathering GuardDuty evidence')
    for region in config['inScopeRegions']:
        guardduty_client = boto3.client('guardduty', region_name=region)
        allDetectors = fetchData(guardduty_client.list_detectors)
        saveJson(allDetectors, f'audit_evidence/GuardDuty/regions/{region}/all_detectors.json')
        for detector_id in allDetectors['DetectorIds']:
            detectorDetails = guardduty_client.get_detector(DetectorId=detector_id)
            saveJson(detectorDetails, f'audit_evidence/GuardDuty/regions/{region}/{detector_id}_config.json')
            if config['GD_Findings']:
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

                # Step 1: List only ACTIVE finding IDs using filter
                findings = []
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

def saveEventBridgeEvidence(config):
    if config['GD_Alerts']:
        print('Gathering EventBridge evidence')
        for region in config['inScopeRegions']:
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

def saveCloudTrailEvidence(config):
    if config['Cloud_Trail_Multi_Region']:
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
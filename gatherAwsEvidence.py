import boto3
import json
import os
import time
from botocore.exceptions import ClientError

def main():
    # TODO: Check in-scope regions.

    # Gather evidence for IAM
    print('Gathering IAM evidence')
    iam_client = boto3.client('iam')
    # Generate credentials report & save to JSON (used for IAM_MFA test).
    iam_client.generate_credential_report()
    time.sleep(5)
    saveJson(iam_client.get_credential_report(), 'audit_evidence/IAM/credentials_report.json')

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

    print('Gathering RDS evidence')
    for region in boto3.Session().get_available_regions('rds'):
        try:
            rds_client = boto3.client('rds', region_name=region)
            allDatabases = fetchData(rds_client.describe_db_instances)
            saveJson(allDatabases, f'audit_evidence/RDS/regions/{region}.json')
        except Exception as e:
            if 'InvalidClientTokenId' in e.response['Error']['Code']:
                # NOTE: Error handling for opt-in only regions (ex. af-south-1).
                # If this error occurs, this region is not utilized doesn't utilize this region.
                pass
            else:
                raise


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
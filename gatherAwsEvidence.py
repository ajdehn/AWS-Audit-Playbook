import boto3
import json
import os
import time
from botocore.exceptions import ClientError

def main():
    # TODO: Check if an 'audit_evidence' folder already exists.

    # Gather evidence for IAM
    gather_IAM_evidence()

def gather_IAM_evidence():
    iam_client = boto3.client('iam')
    # Generate credentials report & save to JSON (used for IAM_MFA test).
    iam_client.generate_credential_report()
    time.sleep(10)
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
    
    """
    # IAM_MFA: Gather evidence for root account
    accountSummary = iam_client.get_account_summary()
    saveJson(accountSummary, 'audit_evidence/IAM/account_summary.json')    


    # IAM_MFA: Save LoginProfile & MFA evidence status for all IAM users.
    for user in allUsers['Users']:
        try:
            # NOTE: If IAM user does not have a console LoginProfile they also won't have MFA.
            loginProfile = iam_client.get_login_profile(UserName=user['UserName'])
            saveJson(loginProfile, f"audit_evidence/IAM/users/{user['UserName']}/login_profile.json")
            mfaList = iam_client.list_mfa_devices(UserName=user['UserName'])
            saveJson(mfaList, f"audit_evidence/IAM/users/{user['UserName']}/mfa_devices.json")
        except ClientError as e:
            if 'NoSuchEntity' in e.response['Error']['Code']:
                # NOTE: IAM user does not have an active console login. 
                pass
            else:
                raise e
    """    

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
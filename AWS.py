import boto3
from ntpath import basename
import json
from time import sleep

# Check if user exists
def user_exists(username, client):
    try: 
        client.get_user(UserName=username)
    except client.exceptions.NoSuchEntityException:
        return False
    return True


# Create IAM user that can operate access keys for requests
def create_user(username, client):
    client.create_user(UserName=username)


# Check if given policy exists
def policy_exists(policy, client):
    policies = client.list_policies(
    Scope='Local',
    PolicyUsageFilter='PermissionsPolicy')

    for cur_policy in policies['Policies']:
        if cur_policy['PolicyName'] == policy:
            return cur_policy['Arn']
    return False


# Limit IAM user privileges to only use services that are required (iam, macie, s3)
def create_policy(name, client):
    # Create a policy
    my_managed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:ListAccessPointsForObjectLambda",
                "iam:GetAccountPasswordPolicy",
                "macie2:ListClassificationJobs",
                "macie2:ListFindingsFilters",
                "macie2:DisableOrganizationAdminAccount",
                "macie2:DescribeOrganizationConfiguration",
                "iam:ListServerCertificates",
                "macie2:GetUsageTotals",
                "s3:PutStorageLensConfiguration",
                "macie2:GetFindingsPublicationConfiguration",
                "iam:ListVirtualMFADevices",
                "iam:SetSecurityTokenServicePreferences",
                "macie2:GetClassificationExportConfiguration",
                "macie2:UntagResource",
                "iam:SimulateCustomPolicy",
                "iam:CreateAccountAlias",
                "macie2:GetFindingStatistics",
                "macie2:DisableMacie",
                "iam:GetAccountAuthorizationDetails",
                "iam:GetCredentialReport",
                "macie2:GetInvitationsCount",
                "macie2:GetMasterAccount",
                "iam:ListPolicies",
                "macie2:ListMembers",
                "s3:PutAccountPublicAccessBlock",
                "iam:ListSAMLProviders",
                "s3:ListJobs",
                "macie2:ListOrganizationAdminAccounts",
                "macie2:TestCustomDataIdentifier",
                "macie2:ListCustomDataIdentifiers",
                "macie2:TagResource",
                "macie2:ListManagedDataIdentifiers",
                "iam:UpdateAccountPasswordPolicy",
                "s3:PutAccessPointPublicAccessBlock",
                "macie2:ListTagsForResource",
                "macie2:SearchResources",
                "macie2:CreateSampleFindings",
                "s3:CreateJob",
                "macie2:GetAdministratorAccount",
                "macie2:DeleteInvitations",
                "iam:GetAccountSummary",
                "macie2:ListFindings",
                "iam:GenerateCredentialReport",
                "macie2:CreateInvitations",
                "s3:GetAccessPoint",
                "macie2:DisassociateFromAdministratorAccount",
                "iam:GetServiceLastAccessedDetailsWithEntities",
                "macie2:EnableMacie",
                "macie2:GetFindings",
                "macie2:DeclineInvitations",
                "macie2:UpdateOrganizationConfiguration",
                "iam:GetServiceLastAccessedDetails",
                "macie2:PutClassificationExportConfiguration",
                "macie2:EnableOrganizationAdminAccount",
                "iam:GetOrganizationsAccessReport",
                "macie2:GetUsageStatistics",
                "macie2:UpdateMacieSession",
                "iam:DeleteAccountAlias",
                "macie2:GetBucketStatistics",
                "macie2:AcceptInvitation",
                "macie2:DisassociateFromMasterAccount",
                "macie2:GetMacieSession",
                "iam:DeleteAccountPasswordPolicy",
                "s3:ListAccessPoints",
                "macie2:PutFindingsPublicationConfiguration",
                "iam:ListRoles",
                "s3:ListMultiRegionAccessPoints",
                "macie2:DescribeBuckets",
                "s3:ListStorageLensConfigurations",
                "iam:GetContextKeysForCustomPolicy",
                "macie2:UpdateMemberSession",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "iam:ListOpenIDConnectProviders",
                "iam:ListAccountAliases",
                "iam:ListUsers",
                "sts:GetCallerIdentity",
                "iam:ListGroups",
                "macie2:ListInvitations"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "s3:*",
                "macie2:*"
            ],
            "Resource": [
                "arn:aws:s3::531117438857:accesspoint/*",
                "arn:aws:s3:::*/*",
                "arn:aws:macie2:*:531117438857:classification-job/*",
                "arn:aws:macie2:*:531117438857:findings-filter/*",
                "arn:aws:macie2:*:531117438857:custom-data-identifier/*",
                "arn:aws:macie2:*:531117438857:member/*",
                "arn:aws:iam::531117438857:oidc-provider/*",
                "arn:aws:iam::531117438857:saml-provider/*",
                "arn:aws:iam::531117438857:mfa/*",
                "arn:aws:iam::531117438857:role/*",
                "arn:aws:iam::531117438857:access-report/*",
                "arn:aws:iam::531117438857:sms-mfa/*",
                "arn:aws:iam::531117438857:group/*",
                "arn:aws:iam::531117438857:policy/*",
                "arn:aws:iam::531117438857:instance-profile/*",
                "arn:aws:iam::531117438857:server-certificate/*",
                "arn:aws:iam::531117438857:user/*"
            ]
        },
        {
            "Sid": "VisualEditor2",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:us-west-2:531117438857:async-request/mrap/*/*",
                "arn:aws:s3:*:531117438857:accesspoint/*",
                "arn:aws:s3:::*",
                "arn:aws:s3:*:531117438857:storage-lens/*",
                "arn:aws:s3-object-lambda:*:531117438857:accesspoint/*",
                "arn:aws:s3:*:531117438857:job/*"
            ]
        }]}

    response = client.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(my_managed_policy)
    )
    
    return response['Policy']['Arn']


# Bind a policy to a user
def bind_policy_to_user(username, policy_arn, client):
    client.attach_user_policy(UserName=username, PolicyArn=policy_arn)


# Create access keys for specific user
def create_access_keys(username, client):
    access_keys = {
        'AccessKeyId' : '' ,
        'SecretAccessKey' : ''
    }

    # Create an access key
    response = client.create_access_key(
        UserName=username
    )
    access_keys['AccessKeyId'] = response['AccessKey']['AccessKeyId']
    access_keys['SecretAccessKey'] = response['AccessKey']['SecretAccessKey'] 

    return access_keys


# Get account id for the created account
def get_accountId(client):
    return client.get_caller_identity().get('Account')


# Check if a s3 bucket exists
def bucket_exists(bucket_name, bucket_object):
    bucket_names = []
    for bucket in bucket_object['Buckets']:
        bucket_names.append(bucket['Name'])

    if bucket_name in bucket_names:
        return True
    else:
        return False


# Create s3 bucket and set it to private
def create_bucket(bucket_name, client):
    # Create Bucket
    client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
            'LocationConstraint': 'eu-west-1'
            },)
    # Make the bucket private and not accessible by the public
    client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
            },)


# Check if the custom email identifier is present
def email_identifier_present(identifiers):
    for item in identifiers['items']:
        if item['name'] == "EMAIL_ADDRESS":
            return True
    return False


# Get email identifier if to be used in classification job
def get_email_identifier_id(client):
    list_identifier_response = client.list_custom_data_identifiers()
    for item in list_identifier_response['items']:
        if item['name'] == 'EMAIL_ADDRESS':
            return item['id']


# wait for the classification job to finish
def wait_for_job(jobId, client):
    
    # Check if classification job is finished
    # -- Display message "WAIT UNTIL JOB FINISHES" --
    jobstatus = ['PAUSED','CANCELLED','IDLE','USER_PAUSED']

    while True:
        describe_job = client.describe_classification_job( jobId=jobId )

        if describe_job['jobStatus'] == 'COMPLETE':
            return True
        if describe_job['jobStatus'] in jobstatus:
            # Job is not runnig and will not finish
            return False

        # Check if job is finished every 60 seconds
        sleep(60)


# Get macie findings
def get_findings(client):
    list_findings = client.list_findings()
    findings_Ids = []
    detailed_findings = []

    for finding in list_findings['findingIds']:
        findings_Ids.append(finding)

    # retrieve findings
    retrieve_findings = client.get_findings( findingIds=findings_Ids )

    for finding in retrieve_findings['findings']:
        detailed_findings.append(finding)

    return detailed_findings


# parse findings into usable data
def parse_results(macie_findings, filename):
    def parse_jsonpath(jsonPath_str):
        # path = index ; data line ; name of field
        split = jsonPath_str.split(".")
        split[0] = int(split[0][2])
        return split
    
    file = open(filename)
    source_file_data = json.load(file)

    sensitive_fields = {}
    results = []

    # Custom identifiers
    # traverse json until reached jsonPath field
    for finding in macie_findings:
        for detection in finding['classificationDetails']['result']['customDataIdentifiers']['detections']:
            for record in detection['occurrences']['records']:
                # Parse Jsonpath into workable data
                jsonpath = parse_jsonpath(record['jsonPath'])
                # find out the table name of the sensitive field
                source_file_data[jsonpath[0]]['name']
                # enter the sensitive field into the dictionary
                sensitive_fields[jsonpath[2]] = source_file_data[jsonpath[0]]['name']
        # enter dictionary into list
        results.append(sensitive_fields.copy())
        sensitive_fields.clear()

        # Macie identifiers
        for detection_category in finding['classificationDetails']['result']['sensitiveData']:
            for detection in detection_category['detections']:
                for record in detection['occurrences']['records']:
                    jsonpath = parse_jsonpath(record['jsonPath'])
                    sensitive_fields[jsonpath[2]] = source_file_data[jsonpath[0]]['name']
        results.append(sensitive_fields.copy())
        sensitive_fields.clear()

    return results


# Delete access keys for a specific user
def delete_access_keys(username, access_key_id, client):
    client.delete_access_key( UserName=username, AccessKeyId=access_key_id)


# Delete object from bucket after processing
def delete_from_bucket(filename, bucket_name, client):
    client.delete_object(
        Bucket=bucket_name,
        Key=filename,)

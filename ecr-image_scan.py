#! /bin/env python3

# imports
import os
import boto3
import io
import csv
import datetime
import time
from dateutil.relativedelta import relativedelta
from botocore.exceptions import ClientError
from sys import argv


def main():

    # var
    REGION = os.environ.get("AWS_REGION")
    S3BUCKET = output-s3-bucket'
    TIMESTAMP = datetime.datetime.now().isoformat()
    CONTROLDATE = datetime.datetime.now() - datetime.timedelta(days=14)
    OLDIMAGE_CONTROLDATE = datetime.datetime.now() - relativedelta(months=+2)

    # functions call
    accountid = account_id(REGION)

    auth_ecr(accountid, REGION)

    alert_status = False
    writereport = True
    repo_names = []

    # get a list of repos
    all_repos = find_repositories(accountid, REGION)

    # if a container image was sepcified
    if len(argv) > 1:

        repo = str(argv[1])

        # make sure that the supplied repo is in the all_repos list
        # TODO: convert this to a generator
        if repo in all_repos:
            print(f"Repo {repo} is a valid ECR repository")
            print("\n")
            repo_names.append(repo)
            writereport = False
        else:
            print(f"Repo {repo} is not a valid ECR repository")
            exit(1)

    # if there is no repo provided in cli
    else:

        # all repos
        repo_names = all_repos

    if writereport:

        # Setup CSV string writer
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
        # CSV Headers
        # writer.writerow(['repo','ImageId','CVE Number','Severity','Affected Package Name'])
        writer.writerow(['Repositoriy', 'ImageId', 'Plugin Id/CVE', 'Risk', 'CVSS2 Score', 'HOST', 'Protocol', 'PORT', 'Name', 'Synopis', 'Description', 'Solution', 'See Also', 'Plugin Output', 'STIG Severity', 'CVSS v3.0 Base Score', 'CVSS v2.0 Temporal Score', 'CVSS v3.0 Temporal Score'])
        writer.writerow('\n')

        

    for repo in repo_names:

        securityscan = []
        deployment_approved = True

        print(repo.capitalize())
        print("-----------------")

        if writereport:
            writer.writerow([repo])
            writer.writerow(['\n'])

        sorted_images = find_images(accountid, repo, REGION)

        # if there are no images to scan
        if not sorted_images:

            print(f'Repo: {repo} has no images, skipping')
            print('\n')

            if writereport:
                writer.writerow(['', f'{repo} has no images to scan'])
                writer.writerow(['\n'])

            continue

        # Get all the images from a repo
        for image in sorted_images:

            # assume all images in a repo are good until the scan is validated.
            image_approved = True

            image_sha = image['imageDigest']

            # need to ensure that the scan data is within policy date
            while True:

                response = get_image_findings(accountid, repo, image, image_sha, REGION)

                # If the image scan has failed alert and write a message.
                if response['imageScanStatus']['status'] == 'FAILED':
                    print("The image scan for " + image_sha + " has failed, troubleshoot!")
                    # if a scan fails there is nothing that can be done from the aws side, you will need to reupload and try again.
                    send_email_alert(accountid, REGION, message="An ECR Scan Has Failed, Investigate!")
                    break

                vulnerabilitysource = response['imageScanFindings']['imageScanCompletedAt']

                if CONTROLDATE.date() > vulnerabilitysource.date():
                    # Force an repo_scan
                    print("Scan is out of date. Updating scan...")

                    # TODO: retool scan_repo with boto waiter
                    scan_repo(repo, image_sha, REGION)
                else:
                    print("Scan is up to date")
                    break

            # Pull out the scan finding, the scan completed time, and the vulnerability database timestamp
            scancompleted = response['imageScanFindings']['imageScanCompletedAt'].isoformat()
            vulnerabilitysource = response['imageScanFindings']['vulnerabilitySourceUpdatedAt']

            # If there are no findings print out a message stating this, if there are findings print out the information
            if len(response['imageScanFindings']['findings']) == 0:
                print(f"Image {image_sha} has no findings, adding to securityscan")

                if writereport:
                    writer.writerow(['', image_sha, 'No Findings to Report'])

            # If there are findings to report
            else:
                # Loop through the findings
                for finding in response['imageScanFindings']['findings']:

                    package_name = next(attribute['value'] for attribute in finding['attributes'] if attribute['key'] == 'package_name')
                    package_version = next(attribute['value'] for attribute in finding['attributes'] if attribute['key'] == 'package_version')
                    cvss2_score = next((attribute['value'] for attribute in finding['attributes'] if attribute['key'] == 'CVSS2_SCORE'), 'N/A')

                    if writereport:
                        # FORMAT
                        # ['Repositoriy', 'ImageId','Plugin Id/CVE','Risk','CVSS2 Score','HOST','Protocol','PORT','Name','Synopis','Description','Solution','See Also','Plugin Output','STIG Severity','CVSS v3.0 Base Score','CVSS v2.0 Temporal Score','CVSS v3.0 Temporal Score'])
                        writer.writerow(['', image_sha, finding['name'], finding['severity'], cvss2_score, 'N/A', ' N/A', 'N/A', package_name, 'package_version: ' + package_version, finding['uri'], 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'])

                    # If A High/Medium/Critical Finding has been found send an alert email for review,do not allow deployment
                    if not (finding['severity'] == "LOW" or finding['severity'] == "UNDEFINED" or finding['severity'] == "INFORMATIONAL"):
                        print(f"A {finding['severity']} finding has been found in {image_sha}, review your scan findings!")
                        image_approved = False

                        # if the email alert has not been tripped for the repo, set now.
                        if not alert_status:
                            alert_status = True

            # if the image meets the scan requirements
            if image_approved:
                print(f"Image {image_sha} has been approved, adding to securityscan")
                securityscan.append(str(image['imageTag']))

        # image level
        # needed due to securityscan will be empty when no images are approved
        if not securityscan:
            deployment_approved = False

        if writereport:
            # add in empty row to report on the approved iamge
            writer.writerow(['\n'])

        # if an image doesn't meet the secuirty standards
        if alert_status:
            print("\n")
            print("Email alert will be sent")
            send_email_alert(accountid, REGION, message=f"An ECR Finding has been found with {repo}, Investigate!")

        # if the image meets the scan requirements
        if deployment_approved:
            print("")
            print(f"Deployment for {repo} is approved")
            print("-----------------------------------")

            # get the old image for update verification
            oldapprovedimage = get_approved_repo_tag(accountid, repo, REGION)

            if oldapprovedimage:
                print(f"The current approved image for {repo} is {oldapprovedimage}")
            else:
                print(f"Currently there is no approvedimage tag for {repo}")

            # update the approvedtag
            update_approved_image(accountid, repo, securityscan, REGION)

            # get the new approved tag
            newapprovedimage = get_approved_repo_tag(accountid, repo, REGION)

            if newapprovedimage:
                # if the image did not change
                if oldapprovedimage == newapprovedimage:
                    print("The approved image did not change, has a new image been built?")
                    print("\n")

                    if writereport:
                        # add in empty row to report on the approved iamge
                        writer.writerow([f'The approvedimage tag equals: {newapprovedimage}'])
                        writer.writerow(['\n'])

                else:
                    print(f"The new approved image for {repo} is: {newapprovedimage}")
                    print("")

                    if writereport:
                        # add in empty row to report on the approved iamge
                        writer.writerow([f'The approvedimage tag equals: {newapprovedimage}'])
                        writer.writerow(['\n'])

            else:
                print(f"There is no approvedimage tag, verify the tags for {repo}")

        # if no images meed the sec requirments, perform tag logic to ensue the tags are up to date and valid
        else:
            print(f"No images in {repo} meet security requirements\n")

            # make sure that the approved image exists in the repository
            oldapprovedimage = get_approved_repo_tag(accountid, repo, REGION)

            # if the oldapproved image is not in the list of returned images
            if oldapprovedimage not in sorted_images:
                # specifal formating: if there are no approved images, no need to remove the tag
                if not oldapprovedimage:
                    print(f"Thre is no approved image tag in the {repo} repository, no need to remove!")
                    print("\n")
                else:
                    print(f"Approved image {oldapprovedimage} is not in the {repo} repository, need to remove tags")
                    remove_old_tags(accountid, repo, REGION)

            if writereport:
                writer.writerow(['', f'No approved image for {repo}'])
                writer.writerow(['\n'])

    if writereport:
        # add the final compliance line to the writer
        writer.writerow(['Container scan completed at: ' + scancompleted + ' UTC Using plugin information timestamp: ' + vulnerabilitysource.isoformat() + ' UTC'])

        # write the final report
        write_s3_report(accountid, output.getvalue(), REGION, S3BUCKET, TIMESTAMP)

    # make sure that there are no old images.
    verify_no_old_images(accountid, repo, securityscan, REGION, OLDIMAGE_CONTROLDATE)


# find the account id
def account_id(REGION: str):

    # get the account id
    sts_client = boto3.client('sts', region_name=REGION)
    aws_account = sts_client.get_caller_identity()
    accountid = aws_account['Account']

    # return the account id
    return accountid


# authenticate and get an ecr token
def auth_ecr(accountid: str, REGION: str):

    ecr_client = boto3.client('ecr', region_name=REGION)

    # Get the ecr auth token
    ecr_client = boto3.client('ecr', region_name=REGION)
    response = ecr_client.get_authorization_token(
        registryIds=[
            # use the accountid from sts_client
            accountid,
        ]
    )

    # grab the auth token - by nesting the first dict key
    auth_token = response['authorizationData'][0]['authorizationToken']

    # return the ecr auth_token
    return auth_token


# find the ecr repos
def find_repositories(accountid: str, REGION: str):

    ecr_client = boto3.client('ecr', region_name=REGION)

    # describe the repositories owned by the current aws account
    response = ecr_client.describe_repositories(
        registryId=accountid,
    )

    # get the full list of repo names
    repos = response['repositories']

    # now parse the repo_names into a list/array
    repo_names = map(lambda repo: repo['repositoryName'], repos)

    return repo_names


def find_images(accountid: str, repo: str, REGION: str):

    ecr_client = boto3.client('ecr', region_name=REGION)

    response = ecr_client.list_images(
        registryId=accountid,
        repositoryName=repo
    )

    if len(response['imageIds']) == 0:
        print(repo + " has no images\n")
        return None
    else:
        sorted_images = sorted(response['imageIds'], key=lambda k: k['imageTag'])
        return sorted_images


def describe_image(accountid: str, repo: str, image_sha: str, REGION: str):

    ecr_client = boto3.client('ecr', region_name=REGION)

    response = ecr_client.describe_images(
        registryId=accountid,
        repositoryName=repo,
        imageIds=[
            {
                'imageDigest': image_sha,
            },
        ]
    )

    return str(response['imageDetails'][0]['imageTags'][0])


def get_image_findings(accountid: str, repo: str, image: str, image_sha: str, REGION: str):

    ecr_client = boto3.client('ecr', region_name=REGION)

    # Get the scan finding based on the image sha
    response = ecr_client.describe_image_scan_findings(
        registryId=accountid,
        repositoryName=repo,
        imageId={
            'imageDigest': image_sha
        }
    )

    return response


def write_s3_report(accountid: str, results: str, REGION: str, S3BUCKET: str, TIMESTAMP: str):

    year = TIMESTAMP[0:4]

    print('--------------------------------')
    print("Sending compliance report to s3.")

    # create the s3 client, and write the results file to s3.
    s3_client = boto3.client('s3', region_name=REGION)
    s3_client.put_object(
        Body=results,
        Bucket=S3BUCKET + "-" + accountid,
        Key='ecr-scans/' + year + '/' + TIMESTAMP + '/ecr-scanreport.csv',
        ServerSideEncryption='aws:kms'
    )


def send_email_alert(accountid: str, REGION: str, message: str, subject='AWS ECR Infrastructure Alert', service='ECR'):

    # create the SNS client
    sns_client = boto3.client('sns', region_name=REGION)

    email_message = '{0} Check the {1} Console for more information.'.format(message, service)

    # Publish the sns mesage
    try:
        response = sns_client.publish(
            TopicArn=f'arn:aws-us-gov:sns:{REGION}:{accountid}:alarms-topic',
            Subject=subject,
            Message=email_message
        )
        print('Sending email...')
        print(response)
    except ClientError as error:
        print(error)
        quit()


# if the scan is out of date, go ahaead and scan it and wait for it to complete.
def scan_repo(repo: str, image_sha: str, REGION: str):

    # create the ecr_client
    ecr_client = boto3.client('ecr', region_name=REGION)

    # scan the image in question
    response = ecr_client.start_image_scan(
        repositoryName=repo,
        imageId={
            'imageDigest': image_sha,
        }
    )

    # print out the message, and sleep for 10 secounds
    print("Starting image scan for: " + image_sha)
    time.sleep(10)

    # start a while loop to and see if the image scan has completed.
    while True:
        response = ecr_client.describe_image_scan_findings(
            repositoryName=repo,
            imageId={
                'imageDigest': image_sha,
            },
        )

        # grab the image scan status
        scan_status = response['imageScanStatus']['status']

        # if the scan status comes back complete then move on
        if scan_status == 'COMPLETE':
            print("Scan has been completed")
            time.sleep(15)
            break
        else:
            time.sleep(15)


def update_approved_image(accountid: str, repo: str, securityscan: str, REGION: str):

    # create the ecr_client
    ecr_client = boto3.client('ecr', region_name=REGION)

    securityscan.sort()

    # get the repo arn
    response = ecr_client.describe_repositories(
        repositoryNames=[
            repo,
        ]
    )

    repo_arn = str(response['repositories'][0]['repositoryArn'])

    # need to perform some tag logic
    response = ecr_client.list_tags_for_resource(
        resourceArn=repo_arn
    )

    # if there is an adminoverride tag
    if response['tags']:
        for tag in response['tags']:
            if tag['Key'] == 'adminoverride':
                print("Need to verify that the adminoverride is not newer then approved image")

                if str(tag['Value']) > str(securityscan[-1]):
                    print("The adminoverride references a newer image, then the one approved")
                    return str(tag['Key'])
                else:
                    print("Approved image is newer then adminoverride, removing tag")

                    # if the approved image is greater the adminoverride can be safely removed
                    response = ecr_client.untag_resource(
                        resourceArn=repo_arn,
                        tagKeys=[
                            str(tag['Key']),
                        ]
                    )
            elif tag['Key'] == 'approvedimage':
                old_image_tag = str(tag['Value'])

                # optimization make sure there is a need to update the tag
                if str(old_image_tag) >= str(securityscan[-1]):
                    return str(tag['Key'])
                else:
                    print(f'Updating approvedimage tag to: {str(securityscan[-1])}')
                    print('\n')
                    # tag the repo with the approved image.
                    response = ecr_client.tag_resource(
                        resourceArn=repo_arn,
                        tags=[
                            {
                                'Key': 'approvedimage',
                                'Value': str(securityscan[-1])
                            },
                        ]
                    )
                    return (str(securityscan[-1]))
    # if there are no tags add approvedimage
    else:
        print(f'Updating approvedimage tag to: {str(securityscan[-1])}')
        print('\n')
        # tag the repo with the approved image.
        response = ecr_client.tag_resource(
            resourceArn=repo_arn,
            tags=[
                {
                    'Key': 'approvedimage',
                    'Value': str(securityscan[-1])
                },
            ]
        )
        return (str(securityscan[-1]))


# remove old tags
def remove_old_tags(accountid: str, repo: str, REGION: str):

    # create the ecr_client
    ecr_client = boto3.client('ecr', region_name=REGION)

    # get the repo arn
    response = ecr_client.describe_repositories(
        repositoryNames=[
            repo,
        ]
    )

    repo_arn = str(response['repositories'][0]['repositoryArn'])

    # need to perform some tag logic
    response = ecr_client.list_tags_for_resource(
        resourceArn=repo_arn
    )

    # if there is an adminoverride tag
    if response['tags']:
        for tag in response['tags']:
            if tag['Key'] == 'adminoverride':
                print(f"There is an adminoverride tag present on the {repo} repository!")
                # response = ecr_client.untag_resource(
                #     resourceArn=repo_arn,
                #     tagKeys=[
                #         str(tag['Key']),
                #     ]
                # )

            if tag['Key'] == 'approvedimage':
                print("Removing approvedimage tag")
                response = ecr_client.untag_resource(
                    resourceArn=repo_arn,
                    tagKeys=[
                        str(tag['Key']),
                    ]
                )

        return None


# verify that the approved image is not to old per policy
def verify_no_old_images(accountid: str, repo: str, securityscan: str, REGION: str, OLDIMAGE_CONTROLDATE: datetime):

    # create the ecr_client
    ecr_client = boto3.client('ecr', region_name=REGION)

    # get the repo arn
    response = ecr_client.describe_repositories(
        repositoryNames=[
            repo,
        ]
    )

    repo_arn = str(response['repositories'][0]['repositoryArn'])

    # need to perform some tag logic
    response = ecr_client.list_tags_for_resource(
        resourceArn=repo_arn
    )

    # if there is an adminoverride/approvedimage tag
    if response['tags']:
        for tag in response['tags']:
            if tag['Key'] == 'adminoverride' or tag['Key'] == 'approvedimage':

                # convert the formatedate in to a datetime
                image_tag = datetime.datetime.strptime(str(tag['Value']), "%Y%m%d-%H%M")

                # if the tag is older then the policy cutoff, send alert
                if OLDIMAGE_CONTROLDATE >= image_tag:
                    print('The ' + str(tag['Key']) + ' tag is older then the defined policy')
                    send_email_alert(accountid, REGION, message=f"An old {str(tag['Key'])} ECR tag has been found in {repo}, Investigate!", tag=str(tag['Key']))


def get_approved_repo_tag(accountid: str, repo: str, REGION: str):

    # create the ecr_client
    ecr_client = boto3.client('ecr', region_name=REGION)

    # get the repo arn
    response = ecr_client.describe_repositories(
        repositoryNames=[
            repo,
        ]
    )

    repo_arn = str(response['repositories'][0]['repositoryArn'])

    # need to perform some tag logic
    response = ecr_client.list_tags_for_resource(
        resourceArn=repo_arn
    )

    # if there is an adminoverride tag
    if response['tags']:
        for tag in response['tags']:
            if tag['Key'] == 'approvedimage':
                return str(tag['Value'])

    return None


if __name__ == "__main__":
    main()

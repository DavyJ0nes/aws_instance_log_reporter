#!/usr/bin/env python
"""
log_checker
  Looks through an AWS account and checks to see if the running instances
  are correctly pushing logs into Cloudwatch Logs

Runs using Python 2.7
DavyJ0nes 2017
"""

import argparse
import csv
import json
import time
import boto3


def main():
    """main function"""
    # SET COMMAND LINE FLAGS
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', action='store', dest='region', default='eu-west-1')
    parser.add_argument('--profile', action='store', dest='profile', default='default')
    parser.add_argument('--hours', action='store', dest='hours', required=True)
    parser.add_argument('--ssm', action='store_true', dest='ssm', default=False)
    parser.add_argument('--debug', action='store_true', dest='debug', default=False)
    parser.add_argument('--csv', action='store_true', dest='csv', default=False)
    parser.add_argument('--json', action='store_true', dest='json', default=False)
    args = parser.parse_args()

    # set boto session parameters
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    # Get Instance Ids fo running Windows Instances
    instance_ids = get_instances(session, 'windows')

    # Get Log Streams of Windows Logs
    log_group_names = get_log_groups(session, '/windows')
    log_streams = []
    for instance in instance_ids:
        log_streams.append(
            get_log_streams(args.debug, session, log_group_names, instance, int(args.hours))
        )
    # This is a simple but slightly hacky way of flattening a list of lists
    log_stream_ids = [y for x in log_streams for y in x]

    # Debug Output
    if args.debug:
        print 'instance_ids:\n{}'.format(instance_ids)
        print '============================================================================'
        print 'log_streams:\n{}'.format(log_stream_ids)

    # Compare instances and log_streams
    existing_logs, missing_logs = compare(args.debug, instance_ids, log_stream_ids)

    if args.ssm:
        ssm_not_active = []
        for missing in missing_logs:
            if ssm_active(args.debug, session, missing):
                ssm_not_active.append(missing)

    ### OUTPUT DATA AS CSV ###
    if args.csv:
        missing_log_instance_info = collate_instance_data(session, args.profile, missing_logs)
        file_name = 'missing_logs-{}.csv'.format(args.profile)
        output_csv(file_name, missing_log_instance_info)

        # output deactivated SSM
        if args.ssm:
            no_ssm_instance_info = []
            for instance_no_ssm in ssm_not_active:
                inst_detailed_info = more_instance_info(session, instance_no_ssm, args.profile)
                no_ssm_instance_info.append(inst_detailed_info)
            file_name = 'no_ssm-{}.csv'.format(args.profile)
            output_csv(file_name, no_ssm_instance_info)

    elif args.json:
        missing_log_instance_info = collate_instance_data(session, args.profile, missing_logs)
        print json.dumps(missing_log_instance_info)

    else:
        ### PRINT SUMMARY OF SCRIPT ###
        print '-------------------------- SUMMARY FOR ENV: {} -----------------------------'.format(args.profile)
        print '============================================================================'
        print 'Instances with Existing Logs in Cloudwatch Logs: {}\n{}'.format(len(existing_logs), existing_logs)
        print '\n============================================================================'
        print 'Instances with Missing Logs in CloudWatch Logs:  {}\n{}'.format(len(missing_logs), missing_logs)
        print '\n============================================================================'
        print 'Count of Running Instances = {} | Count of Missing CloudWatch Logs = {} | Count of SSM Agent Not Active = {}'.format(
            len(instance_ids), len(missing_logs), len(ssm_not_active)
        )
        if args.ssm:
            print '\n============================================================================'
            print 'Instances with SSM Not Configured: {}\n{}'.format(len(ssm_not_active), ssm_not_active)


########## HELPER FUNCTIONS ##########

def get_log_groups(session, prefix):
    """get_loggroups"""
    client = session.client('logs')
    groups = client.describe_log_groups(
        logGroupNamePrefix=prefix
    )

    log_group = []
    for group in groups['logGroups']:
        log_group.append(str(group['logGroupName']))

    return log_group


def get_log_streams(debug, session, log_group_names, instance_id, hours):
    """get_log_streams returns list of log streams that are within the log groups"""
    client = session.client('logs')

    difference = long(hours * 3600)
    start = long((time.time() - difference) * 1000)
    end = long(time.time() * 1000)

    log_streams = []
    for log in log_group_names:
        try:
            response = client.filter_log_events(
                logGroupName=log,
                logStreamNames=[
                    instance_id
                ],
                startTime=start,
                endTime=end,
                limit=10000
            )
        except Exception:
            return []
        # Debug Output
        if debug:
            print 'streams | {}'.format(response['searchedLogStreams'])

        for logs in response['searchedLogStreams']:
            log_streams.append(logs['logStreamName'])

    return log_streams


def get_instances(session, platform):
    """getInstances gets list of windows instance Ids"""
    client = session.client('ec2')
    response = client.describe_instances(
        Filters=[
            {
                'Name': 'platform',
                'Values': [
                    platform
                ]
            },
            {
                'Name': 'instance-state-name',
                'Values': [
                    'running'
                ]
            }
        ]
    )

    ids = []
    for res in response['Reservations']:
        for inst in res['Instances']:
            ids.append(inst['InstanceId'])

    return ids


def compare(debug, instance_array, log_array):
    """Compares two arrays to pull out what is missing"""
    existing_logs = []
    missing_logs = []
    for inst in instance_array:
        if inst in log_array:
            if debug:
                print '{} has log stream'.format(inst)
            existing_logs.append(inst)
        else:
            # Debug Output
            if debug:
                print 'ERROR: {} doesnt have log stream'.format(inst)
            missing_logs.append(inst)

    return existing_logs, missing_logs

def ssm_active(debug, session, instanceid):
    """Checks if SSM Agent is active on the instance"""
    client = session.client('ssm')
    response = client.describe_instance_information(
        Filters=[
            {
                'Key': 'InstanceIds',
                'Values': [
                    instanceid
                ]
            }
        ]
    )
    response_length = len(response['InstanceInformationList'])

    if response_length == 0:
        return False

    # Debug Output
    if debug:
        info = response['InstanceInformationList'][0]
        print '\nssm_active | Response'
        print 'InstanceID:         {}'.format(info['InstanceId'])
        print 'Computer Name:      {}'.format(info['ComputerName'])
        print 'PingStatus:         {}'.format(info['PingStatus'])
        print '\nSSM Info Dump:\n{}'.format(info)

    return True


def collate_instance_data(session, profile, missing_logs_instances):
    """collate_instance_data brings more instance information together"""
    missing_log_instance_info = []
    for instance_missing_logs in missing_logs_instances:
        inst_detailed_info = more_instance_info(session, instance_missing_logs, profile)
        missing_log_instance_info.append(inst_detailed_info)

    return missing_log_instance_info

def more_instance_info(session, instance_id, aws_env):
    """Gets more information about an instance"""
    client = session.client('ec2')
    response = client.describe_instances(
        InstanceIds=[
            instance_id
        ]
    )
    instance_dict = response['Reservations'][0]['Instances'][0]

    owner_tag = get_tag(instance_dict['Tags'], 'Owner')
    ssmconfig_tag = get_tag(instance_dict['Tags'], 'SSMCWconfig')
    role_tag = get_tag(instance_dict['Tags'], 'Role')
    env_tag = get_tag(instance_dict['Tags'], 'Env')
    name_tag = get_tag(instance_dict['Tags'], 'Name')
    team_tag = get_tag(instance_dict['Tags'], 'Team')
    hsn_tag = get_tag(instance_dict['Tags'], 'HSN')
    projectcode_tag = get_tag(instance_dict['Tags'], 'Costcentre_Projectcode')

    try:
        instance_profile = instance_dict['IamInstanceProfile']['Arn']
    except KeyError:
        instance_profile = 'instance profile not set'

    data = {
        'AWS_Environment': aws_env,
        'Instance_Name': name_tag,
        'Instance_ID': instance_dict['InstanceId'],
        'Image_ID': instance_dict['ImageId'],
        'Instance_Type': instance_dict['InstanceType'],
        'Launch_Time': str(instance_dict['LaunchTime']),
        'Instance_Platform': instance_dict['Platform'],
        'VPC_ID': instance_dict['VpcId'],
        'Private_Ip': instance_dict['PrivateIpAddress'],
        'Monitoring_Enabled': instance_dict['Monitoring']['State'],
        'IAM_InstanceProfile': instance_profile,
        'Owner': owner_tag,
        'Role': role_tag,
        'Env': env_tag,
        'Team': team_tag,
        'HSN': hsn_tag,
        'Cost_ProjectCode': projectcode_tag,
        'SSMCWconfig': ssmconfig_tag
    }
    return data


def output_csv(file_name, array):
    """Outputs A Dictionary as a CSV File"""
    try:
        keys = array[0].keys()
        with open(file_name, 'wb') as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(array)
    except IndexError:
        pass


def get_tag(tag_list, wanted_tag):
    """Searches for tag and returns it"""
    for tag in tag_list:
        if tag['Key'].title() == wanted_tag.title():
            return tag['Value']

    return 'Unknown Tag: {}'.format(wanted_tag)


########## INIT ##########

if __name__ == "__main__":
    main()

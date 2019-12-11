#!/Users/bogdan/.virtualenvs/lb/bin/python
import boto3
import requests
import argparse
import sys
from botocore.exceptions import ClientError


def authorize():
    security_group.authorize_ingress(IpPermissions=[
        {
            'FromPort': -1,
            'ToPort': -1,
            'IpProtocol': '-1',
            'IpRanges': [
                {
                    'CidrIp': f'{current_ip}/{cidr_size}',
                    'Description': rule_desc
                },
            ],
        }
    ])


def revoke(ip):
    security_group.revoke_ingress(CidrIp=ip, IpProtocol='-1')


def get_current_ip():
    r = requests.get('http://ipv4.wtfismyip.com/json')
    if not r:
        print('Error: Cannot get current IP address.')
        sys.exit(1)

    response = r.json()
    current_ip = response['YourFuckingIPAddress']
    print(f'Current IP address: {current_ip}')

    return current_ip


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Authorize IP in AWS group')
    parser.add_argument('--clear-ip', action='store_true', help='Remove current/given IP from the security group')
    parser.add_argument('--ip', type=str, help='IP to whitelist')
    parser.add_argument('--group-id', default='sg-c9a04cb0', type=str, help='AWS group ID')
    parser.add_argument('--cidr-size', default=32, type=int, help='CIDR block size (default 32)')
    parser.add_argument('--rule-desc', default='Bogdan', type=str, help='Rule description')

    args = parser.parse_args()
    group_id = args.group_id
    cidr_size = args.cidr_size
    rule_desc = args.rule_desc.lower()
    
    # init
    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(group_id)

    if args.ip:
        current_ip = args.ip
    else:
        current_ip = get_current_ip()
    
    # clear current ip, if wanted
    if args.clear_ip is True:
        revoke(f'{current_ip}/{cidr_size}')
        sys.exit(0)
    
    ips = list(filter(lambda x: 'Description' in x and x['Description'].lower().startswith(rule_desc), 
                      security_group.ip_permissions[0]['IpRanges']))
    ips = [x['CidrIp'] for x in ips]
    if not ips:
        print('No IPs found with that description')
    
    for ip in ips:
        revoke(ip)
    
    try:
        authorize()
    except ClientError as e:
        if 'InvalidPermission.Duplicate' not in str(e):
            raise e
        if not ips: # fix
            revoke(f'{current_ip}/{cidr_size}')
        authorize()
    
    print(f'Successfully authorized IP: {current_ip}')

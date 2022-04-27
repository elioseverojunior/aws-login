#!/usr/bin/env python3

import argparse
import base64
import boto3
import botocore.client
import hashlib
import inquirer
import json
import keyring
import os
import pyotp
import re
import subprocess
import sys

from argparse import ArgumentDefaultsHelpFormatter
from botocore.exceptions import ClientError
from configparser import ConfigParser
from datetime import datetime, timedelta
from dateutil.parser import parse
from dateutil.tz import UTC, tzlocal
from lxml import etree as ET
from onelogin.api.client import OneLoginClient
from pathlib import Path
from signal import signal, SIGINT

VERBOSE_MODE = False
DOCKER_CMD = ['docker', 'run', '--rm', '-t', '-v', f'{Path.home()}/.aws:/root/.aws', 'amazon/aws-cli']

# AWS Variables
AWS_CONFIG_PATH = f'{os.path.join(Path.home(), ".aws", "config")}'
AWS_CREDENTIAL_PATH = f'{os.path.join(Path.home(), ".aws", "credentials")}'
AWS_SSO_CACHE_PATH = f'{os.path.join(Path.home(), ".aws", "sso", "cache")}'
AWS_DEFAULT_REGION = 'us-east-1'
AWS_TOKEN_DURATION_IN_SECONDS = 28800
AWS_REGION = ""

# OneLogin Variables
ONELOGIN_CLIENT_ID = keyring.get_password("onelogin", "client_id")
ONELOGIN_CLIENT_SECRET = keyring.get_password("onelogin", "client_secret")
ONELOGIN_APP_ID = int(keyring.get_password("onelogin", "app_id"))
ONELOGIN_MFA = keyring.get_password("onelogin", "mfa")
ONELOGIN_USERNAME = keyring.get_password("onelogin", "username")
ONELOGIN_PASSWORD = keyring.get_password("onelogin", ONELOGIN_USERNAME)
ONELOGIN_REGION = keyring.get_password("onelogin", "region")
ONELOGIN_SUBDOMAIN = keyring.get_password("onelogin", "subdomain")
ONELOGIN_IP = None
ONELOGIN_FILTER_ROLE = 'devops'
ONELOGIN_ACCOUNTS_MAP = {
    '848684029682': {
        'Account_Name': 'Nickel',
        'Long_Friendly_Name': 'IaC/DevOps Payground',
        'Short_Friendly_Name': 'IaC'
    },
    '584428860865': {
        'Account_Name': 'Bronze',
        'Long_Friendly_Name': 'Sandbox',
        'Short_Friendly_Name': 'SND'
    },
    '549323063936': {
        'Account_Name': 'Silver',
        'Long_Friendly_Name': 'Development/Sit/QA',
        'Short_Friendly_Name': 'Dev/Sit/QA'
    },
    '346482298435': {
        'Account_Name': 'Gold',
        'Long_Friendly_Name': 'Stage/Pre-Production/Production',
        'Short_Friendly_Name': 'STG/Pre-Prod/Prod'
    },
    '650007492008': {
        'Account_Name': 'Platinum',
        'Long_Friendly_Name': 'Platinum',
        'Short_Friendly_Name': 'Platinum'
    }
}


class Colour:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ExplicitDefaultsHelpFormatter(ArgumentDefaultsHelpFormatter):
    def get_help_string(self, action):
        if action.default in (None, False):
            return action.help
        return self.get_help_string(action)


# ArgParse Validation Actions
class AwsSessionDuration(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if int(values) > 28800:
            parser.error(f"Please enter a valid max time duration. Got: {values}")
        setattr(namespace, self.dest, values)


def handler(signal_received, frame):
    print()
    print_error('Cancelled by user')
    exit(0)


def is_empty(any_structure):
    if any_structure:
        return False
    else:
        return True


def get_onelogin_client():
    return OneLoginClient(
        client_id=ONELOGIN_CLIENT_ID,
        client_secret=ONELOGIN_CLIENT_SECRET,
        region=ONELOGIN_REGION
    )


def element_text(node):
    ET.strip_tags(node, ET.Comment)
    return node.text


def get_attributes(saml_response):
    if not saml_response:
        return {}

    saml_response_xml = base64.b64decode(saml_response)
    saml_response_root = ET.fromstring(saml_response_xml)
    NAMESPACES = {
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }
    saml_attributes = {}
    attribute_nodes = saml_response_root \
        .xpath('//saml:AttributeStatement/saml:Attribute', namespaces=NAMESPACES)
    for attribute_node in attribute_nodes:
        attr_name = attribute_node.get('Name')
        values = []
        for attr in attribute_node.iterchildren('{%s}AttributeValue' % NAMESPACES['saml']):
            values.append(element_text(attr))
        saml_attributes[attr_name] = values
    return saml_attributes


def select_onelogin_aws_profile(profiles):
    try:
        questions = [
            inquirer.List(
                'name',
                message='Please select an AWS Role',
                choices=profiles.keys()
            ),
        ]
        answer = inquirer.prompt(questions)
        return answer['name'] if answer else sys.exit(1)
    except Exception as ex:
        print(ex)


def do_aws_sts_with_onelogin(
        aws_region: str,
        aws_role_arn: str,
        aws_principal_arn: str,
        onelogin_saml_response: str,
        aws_token_duration: int = 28800):
    conn = boto3.client('sts', region_name=aws_region,
                        config=botocore.client.Config(signature_version=botocore.UNSIGNED))
    try:
        aws_login_data = conn.assume_role_with_saml(
            RoleArn=aws_role_arn,
            PrincipalArn=aws_principal_arn,
            SAMLAssertion=onelogin_saml_response,
            DurationSeconds=aws_token_duration
        )
        return aws_login_data
    except ClientError as err:
        if hasattr(err, 'message'):
            error_msg = err.message
        else:
            error_msg = err.__str__()
        print(error_msg)
        sys.exit(1)


def onelogin():
    print_msg("Performing OneLogin Authentication")
    onelogin_info_indexed_by_roles = {}
    onelogin_ip = onelogin_profile = None
    profiles = {}

    # Starting OneLogin Client
    client = get_onelogin_client()

    # Preparing Token
    client.prepare_token()

    if hasattr(client, 'ip'):
        onelogin_ip = client.ip

    saml_endpoint_response = client \
        .get_saml_assertion(ONELOGIN_USERNAME, ONELOGIN_PASSWORD, ONELOGIN_APP_ID, ONELOGIN_SUBDOMAIN, onelogin_ip)
    mfa_device_id = mfa_device_type = state_token = None
    mfa_verify_info = {}

    if saml_endpoint_response and saml_endpoint_response.type == "success":
        if saml_endpoint_response.mfa is not None:
            mfa_device_id = saml_endpoint_response.mfa.devices[0].id
            mfa_device_type = saml_endpoint_response.mfa.devices[0].type
            state_token = saml_endpoint_response.mfa.state_token

            mfa_verify_info = {
                'device_id': mfa_device_id,
                'device_type': mfa_device_type,
            }

    if 'authenticator' in mfa_device_type.lower():
        if ONELOGIN_MFA:
            otp_token = pyotp.TOTP(ONELOGIN_MFA).now()
        else:
            print_msg("Enter the OTP Token for %s: " % mfa_verify_info['device_type'])
            otp_token = sys.stdin.readline().strip()
    else:
        print("Enter the OTP Token for %s: " % mfa_verify_info['device_type'])
        otp_token = sys.stdin.readline().strip()

    saml_endpoint_response = client \
        .get_saml_assertion_verifying(ONELOGIN_APP_ID, mfa_device_id, state_token,
                                      otp_token, do_not_notify=True)

    if 'otp_token' not in mfa_verify_info:
        mfa_verify_info.update({'otp_token': otp_token})

    if saml_endpoint_response.saml_response is not None:
        print_msg("\nObtained SAMLResponse from OneLogin to be used at AWS")

    attributes = get_attributes(saml_endpoint_response.saml_response)
    if 'https://aws.amazon.com/SAML/Attributes/Role' not in attributes.keys():
        print("SAMLResponse from Identity Provider does not contain AWS Role info")
    else:
        roles = attributes['https://aws.amazon.com/SAML/Attributes/Role']

        # selected_role = None
        if len(roles) > 1:
            for role in roles:
                principal_arn = role.split(",")[1]
                role_arn = role.split(",")[0]
                role_info = role_arn.split(":")
                account_id = role_info[4]
                role_name = role_info[5].replace("role/", "")

                if role_name not in onelogin_info_indexed_by_roles:
                    onelogin_info_indexed_by_roles[role_name] = {}
                    onelogin_info_indexed_by_roles[role_name].update({'accounts': []})

                onelogin_info_indexed_by_roles[role_name]['accounts'].append({
                    'account_id': account_id,
                    'principal_arn': principal_arn,
                    'role_arn': role_arn,
                })

            for role_name, aws_accounts in onelogin_info_indexed_by_roles.items():
                if ONELOGIN_FILTER_ROLE in role_name:
                    for account in aws_accounts['accounts']:
                        aws_accounts = ONELOGIN_ACCOUNTS_MAP.keys()
                        if account['account_id'] in aws_accounts:
                            name = '{} Account - ({} - {} - {})'.format(
                                ONELOGIN_ACCOUNTS_MAP[account['account_id']]['Account_Name'],
                                account['account_id'],
                                re.sub(r'^onelogin-', '', role_name),
                                ONELOGIN_ACCOUNTS_MAP[account['account_id']]['Long_Friendly_Name'],
                            )
                            profiles.update({name: account})

            print("\nAvailable OneLogin AWS Roles:")
            print("-----------------------------------------------------------------------")
            onelogin_profile = select_onelogin_aws_profile(profiles)
            print("-----------------------------------------------------------------------")

    aws_login_data = do_aws_sts_with_onelogin(AWS_REGION,
                                              profiles[onelogin_profile]['role_arn'],
                                              profiles[onelogin_profile]['principal_arn'],
                                              saml_endpoint_response.saml_response,
                                              AWS_TOKEN_DURATION_IN_SECONDS)

    return aws_login_data


def set_profile_credentials(options, profile_name, use_default=False, aws_sts_login=None):
    if check_if_is_sso_profile(options, profile_name):
        profile_opts = get_aws_profile(profile_name)
        cache_login = get_sso_cached_login(profile_opts)
        credentials = get_sso_role_credentials(profile_opts, cache_login)
    else:
        profile_opts = get_aws_profile(f'profile {profile_name}')
        if aws_sts_login:
            credentials = {
                'accessKeyId': aws_sts_login['Credentials']['AccessKeyId'],
                'secretAccessKey': aws_sts_login['Credentials']['SecretAccessKey'],
                'sessionToken': aws_sts_login['Credentials']['SessionToken']
            }
        else:
            credentials = get_aws_credential(profile_opts, profile_name)

    if options.onelogin:
        store_aws_credentials(options, profile_name, profile_opts, credentials)

    if not use_default:
        store_aws_credentials(options, profile_name, profile_opts, credentials)
    else:
        store_aws_credentials(options, 'default', profile_opts, credentials)
        copy_to_default_profile(profile_name)


def get_aws_profile(profile_name):
    print_msg(f'\nReading profile: [{profile_name}]')
    config = read_config(AWS_CONFIG_PATH)
    profile_opts = config.items(profile_name)
    profile = dict(profile_opts)
    return profile


def get_sso_cached_login(profile):
    print_msg('\nChecking for SSO credentials...')

    cache = hashlib.sha1(profile["sso_start_url"].encode("utf-8")).hexdigest()
    sso_cache_file = f'{os.path.join(AWS_SSO_CACHE_PATH, f"{cache}.json")}'

    if not Path(sso_cache_file).is_file():
        print_error('Current cached SSO login is invalid/missing. Login with the AWS CLI tool or use --login')

    else:
        data = load_json(sso_cache_file)
        now = datetime.now().astimezone(UTC)
        expires_at = parse(data['expiresAt']).astimezone(UTC)

        if data.get('region') != profile['sso_region']:
            print_error('SSO authentication region in cache does not match region defined in profile')

        if now > expires_at:
            print_error('SSO credentials have expired. Please re-validate with the AWS CLI tool or --login option')

        if (now + timedelta(minutes=15)) >= expires_at:
            print_warn('Your current SSO credentials will expire in less than 15 minutes!')

        print_success(f'Found credentials. Valid until {expires_at.astimezone(tzlocal())}')
        return data


def get_sso_role_credentials(profile, login):
    try:
        print_msg('\nFetching short-term CLI/Boto3 session token...')

        client = boto3.client('sso', region_name=profile['sso_region'])
        response = client.get_role_credentials(
            roleName=profile['sso_role_name'],
            accountId=profile['sso_account_id'],
            accessToken=login['accessToken'],
        )

        expires = datetime.utcfromtimestamp(response['roleCredentials']['expiration'] / 1000.0).astimezone(UTC)
        print_success(f'Got session token. Valid until {expires.astimezone(tzlocal())}')

        return response["roleCredentials"]
    except Exception as ex:
        print_error(ex)


def store_aws_credentials(options, profile_name, profile_opts, credentials):
    print_msg(f'\nAdding to credential files under [{profile_name}]')

    if AWS_REGION:
        region = AWS_REGION
    else:
        region = profile_opts.get("region", AWS_DEFAULT_REGION)

    credentials.update({'region': region})
    config = read_config(AWS_CREDENTIAL_PATH)

    if config.has_section(profile_name):
        config.remove_section(profile_name)

    config.add_section(profile_name)
    if credentials.get('accessKeyId') and credentials.get('secretAccessKey') and credentials.get('sessionToken'):
        config.set(profile_name, "aws_access_key_id", credentials["accessKeyId"])
        config.set(profile_name, "aws_secret_access_key ", credentials["secretAccessKey"])
        config.set(profile_name, "aws_session_token", credentials["sessionToken"])
        config.set(profile_name, "region", region)
        config.set(profile_name, "cli_pager", '')
    else:
        for key, value in credentials.items():
            config.set(profile_name, key, value)

    write_config(AWS_CREDENTIAL_PATH, config)


def copy_to_default_profile(profile_name):
    print_msg(f'Copying profile [{profile_name}] to [default]')

    if 'profile ' not in profile_name:
        profile_name = 'profile {}'.format(profile_name)

    config = read_config(AWS_CONFIG_PATH)

    if config.has_section('default'):
        config.remove_section('default')

    config.add_section('default')

    for key, value in config.items(profile_name):
        config.set('default', key, value)

    write_config(AWS_CONFIG_PATH, config)


def select_profile():
    config = read_config(AWS_CONFIG_PATH)

    profiles = []
    for section in config.sections():
        if 'default' != section:
            profiles.append(re.sub(r'^profile ', '', str(section)))
    profiles.sort()

    questions = [
        inquirer.List(
            'name',
            message='Please select an AWS config profile',
            choices=profiles
        ),
    ]
    answer = inquirer.prompt(questions)
    return answer['name'] if answer else sys.exit(1)


def get_aws_credentials_config_parser():
    config = ConfigParser()
    config.read(AWS_CREDENTIAL_PATH)
    return config


def get_aws_credential(profile, profile_name):
    config = get_aws_credentials_config_parser()
    credential_config = dict(config.items(profile_name))
    config_result = {**credential_config, **profile}
    return config_result


def check_if_profile_not_has_aws_key_and_secret(options, profile):
    try:
        if options.onelogin:
            return False
        else:
            config = get_aws_credentials_config_parser()
            key = config.has_option(profile, 'aws_access_key_id')
            secret = config.has_option(profile, 'aws_secret_access_key')
            if not key and not secret:
                return False
            return True
    except Exception as ex:
        print_error(ex)
        sys.exit(1)


def check_if_is_sso_profile(options, profile):
    profile_name = get_aws_credential_section_name(options, profile)
    if not profile_name:
        return True
    else:
        return check_if_profile_not_has_aws_key_and_secret(options, profile_name)


def get_aws_credential_section_name(options, profile):
    config = get_aws_credentials_config_parser()
    profile_name = re.sub(r'^profile ', '', str(profile))
    if config.has_section(profile):
        return profile
    elif config.has_section(profile_name):
        return re.sub(r'^profile ', '', str(profile))


def spawn_cli_for_auth(options, profile, docker=False):
    try:
        if check_if_is_sso_profile(options, profile):
            cmd = DOCKER_CMD if docker else ['aws']
            subprocess.run(cmd + ['sso', 'login', '--profile', re.sub(r'^profile ', '', str(profile))],
                           stderr=sys.stderr,
                           stdout=sys.stdout,
                           check=True)
    except Exception as ex:
        print_error(
            f'\nAn error occurred trying to find AWS CLI version. Do you have AWS CLI Version 2 installed?\n{ex}')
        exit(1)


def print_colour(colour, message, always=False):
    if always or VERBOSE_MODE:
        if os.environ.get('CLI_NO_COLOR', False):
            print(message)
        else:
            print(''.join([colour, message, Colour.ENDC]))


def print_error(message):
    print_colour(Colour.FAIL, message, always=True)
    sys.exit(1)


def print_warn(message):
    print_colour(Colour.WARNING, message, always=True)


def print_msg(message):
    print_colour(Colour.OKBLUE, message)


def print_success(message):
    print_colour(Colour.OKGREEN, message)


def add_prefix(options, name):
    if check_if_is_sso_profile(options, name):
        return f'profile {name}' if name != 'default' else 'default'
    else:
        return name


def read_config(path):
    config = ConfigParser()
    config.read(path)
    return config


def write_config(path, config):
    with open(path, "w") as destination:
        config.write(destination)


def load_json(path):
    try:
        with open(path) as context:
            return json.load(context)
    except ValueError:
        pass


def main():
    parser = argparse.ArgumentParser(
        description='Retrieves AWS credentials from SSO for use with AWS CLI v2/Boto3 apps.',
        usage='''%(prog)s\n''',
        add_help=True,
        formatter_class=ExplicitDefaultsHelpFormatter)

    

    parser.add_argument('profile',
                        action='store',
                        nargs='?',
                        default=None,
                        help='AWS config profile to retrieve credentials for.')

    parser.add_argument('-r', '--region',
                        dest='region',
                        type=str,
                        default='us-east-2',
                        help='AWS Region to override credentials for.')

    parser.add_argument('-d', '--duration',
                        dest='duration',
                        type=int,
                        action=AwsSessionDuration,
                        default=28800,
                        help='Max time AWS Token duration. This is linked with IAM role session expires.')

    parser.add_argument('-q', '--quite',
                        dest='verbose',
                        action='store_false',
                        help='To Not Show verbose output, messages, etc.')

    parser.add_argument('--not-use-default',
                        dest='use_default',
                        action='store_false',
                        help='To not clones selected profile and credentials into the default profile.')

    parser.add_argument('--login',
                        action='store_true',
                        help='Perform an SSO login by default, not just when SSO credentials have expired')

    parser.add_argument('--onelogin',
                        action='store_true',
                        help='Perform an OneLogin SSO login by default, not just when SSO credentials have expired')

    parser.add_argument('--docker',
                        action='store_true',
                        help='Use the docker version of the AWS CLI')

    args = parser.parse_args()

    # validate aws v2
    try:
        cmd = DOCKER_CMD if args.docker else ['aws']
        aws_version = subprocess.run(cmd + ['--version'], capture_output=True).stdout.decode('utf-8')

        if 'aws-cli/2' not in aws_version:
            print_error('\n AWS CLI Version 2 not found. Please install. Exiting.')
            sys.exit(1)

    except Exception as e:
        print_error(
            f'\nAn error occurred trying to find AWS CLI version. Do you have AWS CLI Version 2 installed?\n{e}')
        sys.exit(1)

    global VERBOSE_MODE
    VERBOSE_MODE = args.verbose

    global AWS_REGION
    AWS_REGION = args.region

    global AWS_TOKEN_DURATION_IN_SECONDS
    AWS_TOKEN_DURATION_IN_SECONDS = args.duration

    profile = add_prefix(args, args.profile if args.profile else select_profile())

    aws_login = None
    try:
        if args.onelogin:
            aws_login = onelogin()
        elif args.login:
            spawn_cli_for_auth(args, profile, args.docker)

        set_profile_credentials(args, profile, args.use_default if profile != 'default' else False, aws_login)

        print_success('\nDone\n')
    except Exception as ex:
        print_error(f"\nError: {ex.response['Error']['Code']}. It's raising '{ex.response['Error']['Message']}'")


if __name__ == "__main__":
    signal(SIGINT, handler)
    sys.exit(main())

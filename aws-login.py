#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from argparse import ArgumentDefaultsHelpFormatter
from configparser import ConfigParser
from datetime import datetime, timedelta
from pathlib import Path

import boto3
import inquirer
from dateutil.parser import parse
from dateutil.tz import UTC, tzlocal

VERBOSE_MODE = False
DOCKER_CMD = ['docker', 'run', '--rm', '-t', '-v', f'{Path.home()}/.aws:/root/.aws', 'amazon/aws-cli']

AWS_CONFIG_PATH = f'{os.path.join(Path.home(), ".aws", "config")}'
AWS_CREDENTIAL_PATH = f'{os.path.join(Path.home(), ".aws", "credentials")}'
AWS_SSO_CACHE_PATH = f'{os.path.join(Path.home(), ".aws", "sso", "cache")}'
AWS_DEFAULT_REGION = 'us-east-1'
AWS_REGION = None


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
    def _get_help_string(self, action):
        if action.default in (None, False):
            return action.help
        return super()._get_help_string(action)


def set_profile_credentials(profile_name, use_default=False):
    if check_if_is_sso_profile(profile_name):
        profile_opts = get_aws_profile(profile_name)
        cache_login = get_sso_cached_login(profile_opts)
        credentials = get_sso_role_credentials(profile_opts, cache_login)
    else:
        profile_opts = get_aws_profile(f'profile {profile_name}')
        credentials = get_aws_credential(profile_opts, profile_name)
        pass

    if not use_default:
        store_aws_credentials(profile_name, profile_opts, credentials)
    else:
        store_aws_credentials('default', profile_opts, credentials)
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


def store_aws_credentials(profile_name, profile_opts, credentials):
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
    if credentials.get("accessKeyId") and credentials.get("secretAccessKey") and credentials.get("sessionToken"):
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


def check_if_profile_not_has_aws_key_and_secret(profile):
    config = get_aws_credentials_config_parser()
    key = config.get(profile, 'aws_access_key_id')
    secret = config.get(profile, 'aws_secret_access_key')
    if key is not None and secret is not None:
        return False
    return True


def check_if_is_sso_profile(profile):
    profile_name = get_aws_credential_section_name(profile)
    if not profile_name:
        return True
    else:
        return check_if_profile_not_has_aws_key_and_secret(profile_name)


def get_aws_credential_section_name(profile):
    config = get_aws_credentials_config_parser()
    if config.has_section(profile):
        return profile
    elif config.has_section(re.sub(r'^profile ', '', str(profile))):
        return re.sub(r'^profile ', '', str(profile))


def spawn_cli_for_auth(profile, docker=False):
    if check_if_is_sso_profile(profile):
        cmd = DOCKER_CMD if docker else ['aws']
        subprocess.run(cmd + ['sso', 'login', '--profile', re.sub(r'^profile ', '', str(profile))],
                       stderr=sys.stderr,
                       stdout=sys.stdout,
                       check=True)


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


def add_prefix(name):
    if check_if_is_sso_profile(name):
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
                        help='AWS config profile to retrieve credentials for.')

    parser.add_argument('--region', '-r',
                        dest='region',
                        type=str,
                        default=None,
                        help='AWS Region to override credentials for.')

    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Show verbose output, messages, etc.')

    parser.add_argument('--use-default', '-d',
                        action='store_true',
                        help='Clones selected profile and credentials into the default profile.')

    parser.add_argument('--login',
                        action='store_true',
                        help='Perform an SSO login by default, not just when SSO credentials have expired')

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

    profile = add_prefix(args.profile if args.profile else select_profile())

    try:
        if args.login:
            spawn_cli_for_auth(profile, args.docker)

        set_profile_credentials(profile, args.use_default if profile != 'default' else False)

        print_success('\nDone\n')
    except Exception as ex:
        print_error(f"\nError: {ex.response['Error']['Code']}. It's raising '{ex.response['Error']['Message']}'")


if __name__ == "__main__":
    main()

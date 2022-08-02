#!/usr/bin/env python

import socket
import json
import sys
import os
import re
from subprocess import Popen, PIPE
from pprint import pprint

def run_shell(cmd):
  p = Popen(cmd, stdout=PIPE)
  stdout, stderr = p.communicate()
  if p.returncode != 0:
    sys.exit()
  return stdout

usage = "Usage: get-role-token <role> <mfa-token>"
role = sys.argv[1] if len(sys.argv) > 1 else sys.exit(usage)
token = sys.argv[2] if len(sys.argv) > 2 else sys.exit(usage)

user = json.loads(run_shell(["aws", "iam", "get-user"]))
match = re.compile("arn\:aws\:iam\:\:(\d+):.*").match(user["User"]["Arn"])
account_number = match[1]

token = json.loads(
    run_shell([
        "aws",
        "sts",
        "assume-role",
        "--role-arn",
        f"arn:aws:iam::{account_number}:role/{role}",
        "--role-session-name",
        f'cli.user-{user["User"]["UserName"]}',
        "--serial-number",
        f'arn:aws:iam::{account_number}:mfa/{user["User"]["UserName"]}',
        "--token-code",
        f"{token}",
    ]))

print(f'export AWS_ACCESS_KEY_ID={token["Credentials"]["AccessKeyId"]}')
print(
    f'export AWS_SECRET_ACCESS_KEY={token["Credentials"]["SecretAccessKey"]}')
print(f'export AWS_SESSION_TOKEN={token["Credentials"]["SessionToken"]}')
print(f'export AWS_SECURITY_TOKEN={token["Credentials"]["SessionToken"]}')
print(f'export AWS_ROLE_EXPIRATION={token["Credentials"]["Expiration"]}')
print(f"export AWS_ROLE_NAME={role}")


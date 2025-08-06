# FastWGvpn 

## Overview

`FastWGvpn` rapidly provides a WireGuard VPN hosted in AWS.

## Installation
Make sure the AWS CLI is installed and you have credentials setup

```
https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html
aws configure
```

Clone the repository and set up the environment:
```
git clone https://github.com/MrTurvey/FastWGvpn.git
cd FastWGvpn
pip install -r requirements.txt
nano config.yaml (set your AWS profile)
python FastWGvpn.py
```

## Usage
`FastWGvpn` will use your default or predefined AWS credentials

```
usage: fastwgvpn.py [-h] [--config CONFIG] [--cleanup] [--cleanup-instance CLEANUP_INSTANCE] [--force] [--verbose] [--region REGION] [--profile PROFILE]

AWS WireGuard VPN Setup

options:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Configuration file path
  --cleanup             Clean up all WireGuard resources
  --cleanup-instance CLEANUP_INSTANCE
                        Clean up specific instance ID and related resources
  --force               Force cleanup without confirmation prompts
  --verbose, -v         Enable verbose output
  --region REGION       AWS region (overrides config)
  --profile PROFILE     AWS profile (overrides config)
```
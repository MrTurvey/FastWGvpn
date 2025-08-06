"""
WireGuard VPN Server Setup for AWS
Creates an EC2 instance with WireGuard configured and returns a client config
"""

import boto3
import base64
import subprocess
import time
import json
import sys
import yaml
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Default configuration
DEFAULT_CONFIG = {
    'aws': {'profile': 'default', 'region': 'us-west-2'},
    'ec2': {'instance_type': 't3.micro', 'ami_id': '', 'key_pair_name': 'wireguard-keypair'},
    'security': {'security_group_name': 'wireguard-sg', 'ssh_cidr': '0.0.0.0/0'},
    'wireguard': {
        'port': 51820, 'network': '10.8.0.0/24', 'server_ip': '10.8.0.1',
        'client_ip': '10.8.0.2', 'dns_servers': ['8.8.8.8', '8.8.4.4'], 'keepalive': 25
    },
    'output': {'client_config_file': 'output/client.conf', 'server_info_file': 'output/server-info.json'},
    'advanced': {'setup_timeout': 300, 'verbose': False, 'auto_open_config': False}
}

class WireGuardAWSSetup:
    def __init__(self, config_file=None):
        self.config = self._load_config(config_file)
        self.session = self._create_aws_session()
        self.ec2 = self.session.client('ec2', region_name=self.config['aws']['region'])
        self.ec2_resource = self.session.resource('ec2', region_name=self.config['aws']['region'])
        self.instance = None
        self.server_private_key = None
        self.server_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        
    def _load_config(self, config_file=None):
        """Load configuration from YAML file or use defaults"""
        config = DEFAULT_CONFIG.copy()
        config_paths = [config_file] if config_file else []
        config_paths.extend(['config.yaml', 'wireguard-config.yaml', 'config.yml', 'wireguard-config.yml'])
        
        for path in config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        file_config = yaml.safe_load(f) or {}
                    self._deep_merge(config, file_config)
                    print(f"🎉 Loaded configuration from {path}")
                    break
                except Exception as e:
                    print(f"❌ Warning: Could not load config file {path}: {e}")
        
        # Ensure output directory exists
        os.makedirs('output', exist_ok=True)
        return config
    
    def _deep_merge(self, base_dict, update_dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _create_aws_session(self):
        """Create AWS session with specified profile"""
        profile_name = self.config['aws'].get('profile')
        if profile_name and profile_name != 'default':
            try:
                session = boto3.Session(profile_name=profile_name)
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                if self.config['advanced']['verbose']:
                    print(f"✅ Using AWS profile '{profile_name}' - Account: {identity.get('Arn')}")
                return session
            except Exception as e:
                print(f"❌ Warning: Could not use profile '{profile_name}': {e}")
                print("❌ Falling back to default profile")
        return boto3.Session()
        
    def _generate_keypair(self):
        """Generate WireGuard keypair"""
        private_key = X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return (base64.b64encode(private_bytes).decode('ascii'),
                base64.b64encode(public_bytes).decode('ascii'))
    
    def _get_latest_ami(self):
        """Get the latest Amazon Linux 2023 AMI ID for the region"""
        if self.config['ec2']['ami_id']:
            return self.config['ec2']['ami_id']
        
        try:
            response = self.ec2.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['al2023-ami-*-x86_64']},
                    {'Name': 'state', 'Values': ['available']},
                    {'Name': 'architecture', 'Values': ['x86_64']},
                    {'Name': 'virtualization-type', 'Values': ['hvm']}
                ]
            )
            
            images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
            if images:
                ami_id = images[0]['ImageId']
                if self.config['advanced']['verbose']:
                    print(f"🟩 Using latest Amazon Linux 2023 AMI: {ami_id}")
                return ami_id
            else:
                raise Exception("No suitable AMI found")
                
        except Exception as e:
            print(f"❌ Error finding AMI: {e}")
            fallback_amis = {
                'us-west-2': 'ami-0c2d3e23b7e52a26e',
                'us-east-1': 'ami-0c02fb55956c7d316',
                'eu-west-1': 'ami-0c1bc246476a5572b',
                'ap-southeast-1': 'ami-0c802847a7dd848c0'
            }
            region = self.config['aws']['region']
            if region in fallback_amis:
                print(f"🟩 Using fallback AMI for {region}: {fallback_amis[region]}")
                return fallback_amis[region]
            else:
                raise Exception(f"No AMI available for region {region}")
    
    def _get_default_vpc(self):
        """Get default VPC ID"""
        vpcs = self.ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        return vpcs['Vpcs'][0]['VpcId']
    
    def _key_pair_exists(self, key_name):
        """Check if key pair exists"""
        try:
            self.ec2.describe_key_pairs(KeyNames=[key_name])
            return True
        except self.ec2.exceptions.ClientError:
            return False
    
    def create_key_pair(self):
        """Create EC2 key pair if it doesn't exist"""
        key_name = self.config['ec2']['key_pair_name']
        if self._key_pair_exists(key_name):
            print(f"🟩 Key pair {key_name} already exists")
            return True
        
        print(f"🟩 Creating key pair {key_name}...")
        response = self.ec2.create_key_pair(KeyName=key_name)
        
        key_file = f"output/{key_name}.pem"
        with open(key_file, 'w') as f:
            f.write(response['KeyMaterial'])
        
        os.chmod(key_file, 0o400)
        print(f"🟩 Private key saved to {key_file}")
        return True
    
    def create_security_group(self):
        """Create security group for WireGuard"""
        sg_name = self.config['security']['security_group_name']
        vpc_id = self._get_default_vpc()
        
        # Check if security group exists
        try:
            response = self.ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [sg_name]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"🟩 Security group {sg_name} already exists: {sg_id}")
                return sg_id
        except:
            pass
        
        # Create security group
        print(f"🟩 Creating security group {sg_name}...")
        response = self.ec2.create_security_group(
            GroupName=sg_name,
            Description='WireGuard VPN Security Group',
            VpcId=vpc_id
        )
        sg_id = response['GroupId']
        
        # Add rules
        self.ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'udp',
                    'FromPort': self.config['wireguard']['port'],
                    'ToPort': self.config['wireguard']['port'],
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'WireGuard VPN'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': self.config['security']['ssh_cidr'], 'Description': 'SSH'}]
                }
            ]
        )
        
        print(f"🟩 Security group created: {sg_id}")
        return sg_id
    
    def _create_user_data_script(self):
        """Generate user data script to install and configure WireGuard"""
        # Generate server and client keypairs
        self.server_private_key, self.server_public_key = self._generate_keypair()
        self.client_private_key, self.client_public_key = self._generate_keypair()
        
        wg_config = self.config['wireguard']
        
        user_data = f"""#!/bin/bash
yum update -y && yum install -y wireguard-tools iptables-nft iptables-services
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf && sysctl -p
MAIN_INTERFACE=$(ip route | grep default | awk '{{print $5}}' | head -n1)

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = {self.server_private_key}
Address = {wg_config['server_ip']}/{wg_config['network'].split('/')[1]}
ListenPort = {wg_config['port']}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE

[Peer]
PublicKey = {self.client_public_key}
AllowedIPs = {wg_config['client_ip']}/32
EOF

chmod 600 /etc/wireguard/wg0.conf
systemctl enable wg-quick@wg0 && systemctl start wg-quick@wg0
echo "WireGuard setup completed at $(date)" > /tmp/wireguard-setup-complete
"""
        return base64.b64encode(user_data.encode()).decode()
    
    def launch_instance(self, security_group_id):
        """Launch EC2 instance with WireGuard"""
        user_data = self._create_user_data_script()
        ami_id = self._get_latest_ami()
        
        print("🟩 Launching EC2 instance...")
        response = self.ec2.run_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType=self.config['ec2']['instance_type'],
            KeyName=self.config['ec2']['key_pair_name'],
            SecurityGroupIds=[security_group_id],
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': 'WireGuard-VPN-Server'},
                    {'Key': 'Purpose', 'Value': 'VPN'},
                    {'Key': 'CreatedBy', 'Value': 'WireGuard-Setup-Script'}
                ]
            }]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        self.instance = self.ec2_resource.Instance(instance_id)
        
        print(f"🟩 Instance launched: {instance_id}")
        print("🟩 Waiting for instance to be running...")
        
        self.instance.wait_until_running()
        self.instance.reload()
        return instance_id
    
    def wait_for_setup(self):
        """Wait for WireGuard setup to complete"""
        print("🟩 Waiting for WireGuard setup to complete...")
        timeout = self.config['advanced']['setup_timeout']
        
        for attempt in range(timeout // 10):
            time.sleep(10)
            if attempt > 5:  # Give it at least 1 minute
                print("🟩 Setup should be complete (estimated)")
                break
            if self.config['advanced']['verbose']:
                print(f"🟩 Setup progress: {attempt + 1}/{timeout // 10}")
    
    def generate_client_config(self):
        """Generate client configuration file"""
        if not self.instance.public_ip_address:
            print("❌ Error: Instance has no public IP address")
            return None
        
        wg_config = self.config['wireguard']
        dns_servers = ', '.join(wg_config['dns_servers'])
        
        client_config = f"""[Interface]
PrivateKey = {self.client_private_key}
Address = {wg_config['client_ip']}/32
DNS = {dns_servers}

[Peer]
PublicKey = {self.server_public_key}
Endpoint = {self.instance.public_ip_address}:{wg_config['port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {wg_config['keepalive']}
"""
        
        config_file = "output/client.conf"
        with open(config_file, 'w') as f:
            f.write(client_config)
        
        return client_config
    
    def save_server_info(self, instance_id):
        """Save server information to JSON file"""
        server_info = {
            'instance_id': instance_id,
            'public_ip': self.instance.public_ip_address,
            'region': self.config['aws']['region'],
            'instance_type': self.config['ec2']['instance_type'],
            'wireguard_port': self.config['wireguard']['port'],
            'key_pair_name': self.config['ec2']['key_pair_name'],
            'security_group': self.config['security']['security_group_name'],
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'server_public_key': self.server_public_key
        }
        
        info_file = "output/server-info.json"
        with open(info_file, 'w') as f:
            json.dump(server_info, f, indent=2)
        
        if self.config['advanced']['verbose']:
            print(f"Server information saved to {info_file}")
        
        return server_info
    
    def _get_instances_to_cleanup(self, instance_id=None):
        """Get list of instances to clean up"""
        if instance_id:
            return [instance_id]
        
        try:
            response = self.ec2.describe_instances(
                Filters=[
                    {'Name': 'tag:CreatedBy', 'Values': ['WireGuard-Setup-Script']},
                    {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping', 'pending']}
                ]
            )
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance['InstanceId'])
                    print(f"🧹 Found instance to terminate: {instance['InstanceId']} ({instance.get('State', {}).get('Name', 'unknown')})")
            return instances
        except Exception as e:
            print(f"❌ Error finding instances: {e}")
            return []
    
    def _terminate_instances(self, instances, force):
        """Terminate EC2 instances"""
        if not instances:
            print("✅ No instances found to terminate")
            return True
        
        if not force:
            response = input(f"❓ Terminate {len(instances)} instances? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("❌ Instance termination cancelled")
                return False
        
        try:
            print(f"🧹 Terminating {len(instances)} instances...")
            self.ec2.terminate_instances(InstanceIds=instances)
            
            if self.config['advanced']['verbose']:
                print("🧹 Waiting for instances to terminate...")
                for instance_id in instances:
                    instance = self.ec2_resource.Instance(instance_id)
                    instance.wait_until_terminated()
            
            print(f"✅ Terminated {len(instances)} instances")
            return True
        except Exception as e:
            print(f"❌ Error terminating instances: {e}")
            return False
    
    def _delete_security_group(self, force, wait_for_instances=False):
        """Delete security group"""
        print("🧹 Looking for security group to delete...")
        sg_name = self.config['security']['security_group_name']
        
        try:
            vpc_id = self._get_default_vpc()
            response = self.ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [sg_name]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            
            if not response['SecurityGroups']:
                print("✅ No security group found to delete")
                return True
            
            sg_id = response['SecurityGroups'][0]['GroupId']
            
            if not force:
                response = input(f"❓ Delete security group '{sg_name}' ({sg_id})? (y/N): ")
                if response.lower() not in ['y', 'yes']:
                    print("❌ Security group deletion cancelled")
                    return False
            
            if wait_for_instances:
                print("🧹 Waiting for instances to fully terminate before deleting security group...")
                time.sleep(30)
            
            self.ec2.delete_security_group(GroupId=sg_id)
            print(f"✅ Deleted security group: {sg_name}")
            return True
            
        except Exception as e:
            print(f"❌ Error deleting security group: {e}")
            if "DependencyViolation" in str(e):
                print("💡 Try again in a few minutes after instances are fully terminated")
            return False
    
    def _delete_key_pair(self, force):
        """Delete key pair and local key file"""
        print("🧹 Checking key pair...")
        key_name = self.config['ec2']['key_pair_name']
        
        try:
            response = self.ec2.describe_key_pairs(KeyNames=[key_name])
            if not response['KeyPairs']:
                print("✅ No key pair found to delete")
                return True
                
            if not force:
                response = input(f"❓ Delete key pair '{key_name}'? This will also delete the local .pem file. (y/N): ")
                if response.lower() not in ['y', 'yes']:
                    print("❌ Key pair deletion cancelled")
                    return False
            
            self.ec2.delete_key_pair(KeyName=key_name)
            print(f"✅ Deleted key pair: {key_name}")
            
            # Delete local key file
            key_file = f"output/{key_name}.pem"
            if os.path.exists(key_file):
                os.remove(key_file)
                print(f"✅ Deleted local key file: {key_file}")
            
            return True
            
        except self.ec2.exceptions.ClientError:
            print("✅ No key pair found to delete")
            return True
        except Exception as e:
            print(f"❌ Error deleting key pair: {e}")
            return False
    
    def _delete_local_files(self, force):
        """Delete local configuration files"""
        print("🧹 Cleaning up local files...")
        local_files = ["output/client.conf", "output/server-info.json"]
        
        deleted_any = False
        for file_path in local_files:
            if os.path.exists(file_path):
                if not force:
                    response = input(f"❓ Delete local file '{file_path}'? (y/N): ")
                    if response.lower() not in ['y', 'yes']:
                        print(f"❌ File deletion cancelled: {file_path}")
                        continue
                
                try:
                    os.remove(file_path)
                    print(f"✅ Deleted local file: {file_path}")
                    deleted_any = True
                except Exception as e:
                    print(f"❌ Error deleting file {file_path}: {e}")
        
        return deleted_any
    
    def cleanup_resources(self, instance_id=None, force=False):
        """Clean up AWS resources created by this script"""
        print("\n=== WireGuard VPN Cleanup ===")
        
        errors = []
        cleaned_up = False
        
        try:
            # Terminate instances
            instances = self._get_instances_to_cleanup(instance_id)
            if self._terminate_instances(instances, force):
                cleaned_up = True
            
            # Delete security group
            if self._delete_security_group(force, wait_for_instances=bool(instances)):
                cleaned_up = True
                
            # Delete key pair
            if self._delete_key_pair(force):
                cleaned_up = True
            
            # Delete local files
            if self._delete_local_files(force):
                cleaned_up = True
            
            # Summary
            print("\n=== Cleanup Summary ===")
            if cleaned_up:
                print("✅ Cleanup completed successfully!")
            else:
                print("❌ No resources were cleaned up")
            
            return cleaned_up
            
        except Exception as e:
            print(f"❌ Unexpected error during cleanup: {e}")
            if self.config['advanced']['verbose']:
                import traceback
                traceback.print_exc()
            return False
    
    def run(self):
        """Main execution function"""
        try:
            print("\n=== AWS WireGuard VPN Setup ===")
            print(f"🟩 Region: {self.config['aws']['region']}")
            print(f"🟩 Profile: {self.config['aws']['profile']}")
            
            # Create resources
            if not self.create_key_pair():
                return False
            
            sg_id = self.create_security_group()
            if not sg_id:
                return False
            
            instance_id = self.launch_instance(sg_id)
            self.wait_for_setup()
            
            # Generate outputs
            server_info = self.save_server_info(instance_id)
            client_config = self.generate_client_config()
            
            if not client_config:
                return False
            
            # Display results
            print("\n=== Server Information ===")
            print(f"🟩 Instance ID: {instance_id}")
            print(f"🟩 Public IP: {self.instance.public_ip_address}")
            print(f"🟩 Region: {self.config['aws']['region']}")
            print(f"🟩 Instance Type: {self.config['ec2']['instance_type']}")
            
            if not self.config['advanced']['verbose']:
                print("\n=== Client Config Contents ===")
                print("-" * 50)
                print(client_config)
                print("-" * 50)
            
            key_file = f"output/{self.config['ec2']['key_pair_name']}.pem"
            print("\n=== SSH Access ===")
            print(f"🟩 ssh -i {key_file} ec2-user@{self.instance.public_ip_address}")
            
            print(f"\n=== Files Created ===")
            print(f"🟩 Client config: output/client.conf")
            print(f"🟩 Server info: output/server-info.json")
            if os.path.exists(key_file):
                print(f"🟩 SSH key: {key_file}")
                    
            # Auto-open config if requested
            if self.config['advanced']['auto_open_config']:
                try:
                    opener = {"darwin": "open", "linux": "xdg-open", "win32": "notepad"}
                    if sys.platform in opener:
                        subprocess.call([opener[sys.platform], "output/client.conf"])
                except:
                    pass  # Ignore errors in auto-opening
            
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            if self.config['advanced']['verbose']:
                import traceback
                traceback.print_exc()
            return False

def validate_aws_credentials(setup):
    """Validate AWS credentials"""
    try:
        sts = setup.session.client('sts')
        identity = sts.get_caller_identity()
        print(f"Using AWS Account: {identity.get('Account')}")
        if setup.config['advanced']['verbose']:
            print(f"Profile: {setup.config['aws']['profile']}")
            print(f"Region: {setup.config['aws']['region']}")
        return True
    except Exception as e:
        print("❌ AWS credentials not configured properly")
        print(f"Make sure profile '{setup.config['aws']['profile']}' exists in ~/.aws/credentials")
        print("Configure with: aws configure")
        print(f"Error: {e}")
        return False

def check_dependencies():
    """Check for required dependencies"""
    try:
        import boto3
        import yaml
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        return True
    except ImportError as e:
        print(f"❌ Missing required dependency: {e}")
        print("Install with: pip install boto3 pyyaml cryptography")
        return False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS WireGuard VPN Setup')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--cleanup', action='store_true', help='Clean up all WireGuard resources')
    parser.add_argument('--cleanup-instance', help='Clean up specific instance ID and related resources')
    parser.add_argument('--force', action='store_true', help='Force cleanup without confirmation prompts')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--region', help='AWS region (overrides config)')
    parser.add_argument('--profile', help='AWS profile (overrides config)')
    
    args = parser.parse_args()
    
    if not check_dependencies():
        return
    
    # Create setup instance
    setup = WireGuardAWSSetup(config_file=args.config)
    
    # Override config with CLI args
    if args.verbose:
        setup.config['advanced']['verbose'] = True
    if args.region:
        setup.config['aws']['region'] = args.region
    if args.profile:
        setup.config['aws']['profile'] = args.profile
    
    # Recreate AWS session with proper config
    setup.session = setup._create_aws_session()
    setup.ec2 = setup.session.client('ec2', region_name=setup.config['aws']['region'])
    setup.ec2_resource = setup.session.resource('ec2', region_name=setup.config['aws']['region'])
    
    if not validate_aws_credentials(setup):
        return
    
    # Handle cleanup operations
    if args.cleanup or args.cleanup_instance:
        if args.cleanup:
            success = setup.cleanup_resources(force=args.force)
        else:
            success = setup.cleanup_resources(instance_id=args.cleanup_instance, force=args.force)
        
        print(f"\n{'✅ Cleanup completed!' if success else '❌ Cleanup failed or was cancelled!'}")
        sys.exit(0 if success else 1)
    
    # Normal setup operation
    success = setup.run()
    
    if success:
        print("\n✅ WireGuard VPN setup completed successfully!")
        print(f"\n💡 To clean up resources later, run:")
        print(f"   python {sys.argv[0]} --cleanup")
    else:
        print("❌ Setup failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()

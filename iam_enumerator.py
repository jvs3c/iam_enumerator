import boto3
import json
import logging
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Configure logging to output to the console with color
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Vulnerable IAM actions to check
VULNERABLE_ACTIONS = {
    "iam:CreatePolicyVersion": "Create a new policy version",
    "iam:SetDefaultPolicyVersion": "Set a default policy version",
    "iam:PassRole": "Pass an IAM role",
    "ec2:RunInstances": "Run EC2 instances",
    "iam:CreateAccessKey": "Create access keys",
    "iam:CreateLoginProfile": "Create login profile",
    "iam:UpdateLoginProfile": "Update login profile",
    "iam:AttachUserPolicy": "Attach a managed policy to a user",
    "iam:AttachGroupPolicy": "Attach a managed policy to a group",
    "iam:AttachRolePolicy": "Attach a managed policy to a role",
    "iam:PutUserPolicy": "Put an inline policy on a user",
    "iam:PutGroupPolicy": "Put an inline policy on a group",
    "iam:PutRolePolicy": "Put an inline policy on a role",
    "iam:AddUserToGroup": "Add a user to a group",
    "iam:UpdateAssumeRolePolicy": "Update the assume role policy",
    "lambda:CreateFunction": "Create a Lambda function",
    "lambda:InvokeFunction": "Invoke a Lambda function",
    "lambda:UpdateFunctionCode": "Update a Lambda function's code",
    "glue:CreateDevEndpoint": "Create a Glue development endpoint",
    "glue:GetDevEndpoint": "Get a Glue development endpoint",
    "cloudformation:CreateStack": "Create a CloudFormation stack",
    "datapipeline:CreatePipeline": "Create a Data Pipeline",
    "datapipeline:PutPipelineDefinition": "Put a Data Pipeline definition",
    "datapipeline:ActivatePipeline": "Activate a Data Pipeline",
}

def print_banner():
    """Print a fancy banner for the IAM enumerator."""
    banner = f"""
    ██╗ █████╗ ███╗   ███╗   ███████╗███╗   ██╗███╗   ███╗
    ██║██╔══██╗████╗ ████║   ██╔════╝████╗  ██║████╗ ████║
    ██║███████║██╔████╔██║██║█████╗  ██╔██╗ ██║██╔████╔██║
    ██║██╔══██║██║╚██╔╝██║██║██╔══╝  ██║╚██╗██║██║╚██╔╝██║
    ██║██║  ██║██║ ╚═╝ ██║   ███████╗██║ ╚████║██║ ╚═╝ ██║
    ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝
                                                                  
                      IAM:enum by jvs3
    """
    print(banner)

def enumerate_iam_policies(iam_client, output_file):
    """Enumerate IAM policies attached to users and check for risky actions."""
    try:
        # List all IAM users
        users = iam_client.list_users()['Users']

        # Process each user
        for user in users:
            user_name = user['UserName']
            logging.info(f"{Fore.YELLOW}[*] Processing user: {user_name}")

            # List attached managed policies for the user
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']

            # Process each attached managed policy
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                logging.info(f"{Fore.GREEN}[*] Checking attached managed policy: {policy_arn} for user: {user_name}")

                # Get the policy version information
                policy_info = iam_client.get_policy(PolicyArn=policy_arn)
                default_version_id = policy_info['Policy']['DefaultVersionId']

                # Get the policy document for the default version
                policy_document = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version_id
                )['PolicyVersion']['Document']

                # Check for vulnerabilities in the managed policy
                check_policy_vulnerabilities(policy_document, user_name, 'managed policy', output_file)

            # List inline policies for the user
            inline_policies = iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline_policies['PolicyNames']:
                logging.info(f"{Fore.MAGENTA}[*] Checking inline policy: {policy_name} for user: {user_name}")

                # Get the inline policy document
                inline_policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']

                # Check for vulnerabilities in the inline policy
                check_policy_vulnerabilities(inline_policy_document, user_name, 'inline policy', output_file)

    except Exception as e:
        logging.error(f"{Fore.RED}Error processing IAM policies: {e}")

def check_policy_vulnerabilities(policy_document, user_name, policy_type, output_file):
    """Check the policy document for risky actions."""
    # Extract the policy statement(s)
    statements = policy_document.get('Statement', [])

    if isinstance(statements, dict):  # Single statement case
        statements = [statements]

    # Iterate over the statements
    for statement in statements:
        actions = statement.get('Action')

        if isinstance(actions, str):
            actions = [actions]

        if actions is None:
            continue

        risky_actions = [action for action in actions if action in VULNERABLE_ACTIONS]

        if risky_actions:
            # Log risky actions
            with open(output_file, 'a') as f:
                for action in risky_actions:
                    f.write(f"User: {user_name}, Policy: {policy_type}, Risky Action: {action} - {VULNERABLE_ACTIONS[action]}\n")
            logging.info(f"{Fore.RED}[*] Found risky actions for user {user_name}: {', '.join(risky_actions)}")

if __name__ == '__main__':
    # Print the fancy banner
    print_banner()

    # Initialize AWS IAM client
    iam_client = boto3.client('iam')

    # Output file to save results
    output_file = "output.txt"

    logging.info(f"{Fore.BLUE}Starting IAM policy enumeration...")

    # Start enumerating policies
    enumerate_iam_policies(iam_client, output_file)

    logging.info(f"{Fore.GREEN}IAM policy enumeration completed.")

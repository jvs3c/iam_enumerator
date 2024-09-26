This script detects potential privilege escalation vulnerabilities in AWS IAM policies. 
Enumerates all IAM users in the account and checks both attached managed policies and inline policies for risky actions.
The script specifically checks for the following IAM actions that could allow privilege escalation:



Example Output
User: user1, Policy: managed policy, Risky Action: iam:CreatePolicyVersion - Create a new policy version
User: user2, Policy: inline policy, Risky Action: iam:PassRole - Pass an IAM role

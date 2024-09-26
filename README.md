This script detects potential privilege escalation vulnerabilities in AWS IAM policies. 

Enumerates all IAM users in the account and checks both attached managed policies and inline policies for risky actions.

The script specifically checks for the following IAM actions that could allow privilege escalation:


This script detects potential privilege escalation vulnerabilities in AWS IAM policies. Enumerates all IAM users in the account and checks both attached managed policies and inline policies for risky actions.
The script specifically checks for the following IAM actions that could allow privilege escalation:
- iam:AddUserToGroup
- iam:AttachGroupPolicy
- iam:AttachRolePolicy
- iam:AttachUserPolicy
- iam:CreateAccessKey
- iam:CreateLoginProfile
- iam:CreatePolicyVersion
- iam:PassRole and ec2:RunInstances
- iam:PassRole, cloudformation:CreateStack, and cloudformation:DescribeStacks
- iam:PassRole, datapipeline:CreatePipeline, datapipeline:PutPipelineDefinition, and datapipeline:ActivatePipeline
- iam:PassRole, glue:CreateDevEndpoint, and glue:GetDevEndpoint(s)
- iam:PassRole, lambda:CreateFunction, and lambda:CreateEventSourceMapping
- iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction
- iam:PutGroupPolicy
- iam:PutRolePolicy
- iam:PutUserPolicy
- iam:SetDefaultPolicyVersion
- iam:UpdateAssumeRolePolicy
- iam:UpdateLoginProfile
- 
### How to run
git clone https://github.com/jvs3c/iam_enumerator
.\\iam_enumerator.py -k "aws_access_key_id" -s "aws_secret_access_key" -o output.txt

### Example Output
```
User: user1, Policy: managed policy, Risky Action: iam:CreatePolicyVersion - Create a new policy version 
User: user2, Policy: inline policy, Risky Action: iam:PassRole - Pass an IAM role
```

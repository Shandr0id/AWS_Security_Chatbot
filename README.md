# WHAT I AM: This is a MVP demo utility for a human-interactive chatbot that an end user can connect with their AWS account(s) to ask it security questions specifically about their environment.

# WHAT I DO: 
# I Answer questions about:
        - WHOAMI: Gives user basic account and user information

        - S3: Scans for public exposure, including legancy permission checks, for a multi-angled security review

        - EC2: [Given IP] Scans EC2 for type, exposure to the internet and can list open ports (which is much more layered and nuanced in AWS networking than the basic MVP here). You can ask it for basic advice on how to secure these problems.

        - IAM/IDENTITY CENTER: Connects with Identity Center and scans user permission sets/account access and can answer broadly "Who has admin access", and specifically "What permissions does user X have?" (Identity Center is a harder API to work with, requires special perms, and is better security architecture which is why I selected it over IAM for this challenge)

                *NOTE 1: Account using the AWS chatbot must have explicit SSO inline policies, that AWS managed policies do not provide, to operate correctly (please refer to images)*
                *NOTE 2: Project assumes region is us-east-1 is all that exists in the universe*

# HOW I WORK:
1. Import .env variables, OpenAI API key, SSO profiles
2. CLI loop -> LLM -> LangChain Tool router -> boto3/AWS APIs -> humanoid answer to user
*NOTE 3: I included all tools in main.py. Best practice would be to put each tool in its own .py file as they expand and requiring refactoring over time!*


# HOW I RUN:
Python venv setup
pip install -r requirements.txt
Create .env with OPENAI_API_KEY=<your_key>
Configure AWS SSO profiles  https://docs.aws.amazon.com/cli/latest/reference/

After your profile is configured:
aws sso login --profile <your_profile>
            export AWS_PROFILE=<your_profile>
            export AWS_REGION=<your_region>
            python aws_sec_chatbot/main.py

# TOOLS USED IN THIS PROJECT:
- OpenAI's API: https://openai.com/index/openai-api/
- LangGraph/LangChain: https://docs.langchain.com/oss/python/langchain/overview, https://reference.langchain.com/python/langchain/agents/
- AWS CLI, and my own AWS management account (where Identity Center lives) /sub account (where resources interrogated in example output lived):                 https://docs.aws.amazon.com/cli/latest/reference/
- AWS API (and boto3) Documentation: https://docs.aws.amazon.com/, https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
- VS Code
- MacOS
- ChatGPT 5.2

# A NOTE:
- Used AI code editors to compose the base modules (individual tools), written here. Architecture, composition, secure code review and manual revisions, testing and packaging is original work.

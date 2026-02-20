# My variables
from dotenv import load_dotenv
load_dotenv()

# AWS CLI
import os
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

# Langchain
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain.agents import create_agent

@tool("sts_whoami")
def sts_whoami() -> str:
    """Return the AWS account and caller ARN."""
    ident = boto3.client("sts").get_caller_identity()
    return f"Account={ident['Account']} Arn={ident['Arn']}"


SYSTEM = """You are an AWS security assistant.

NON-NEGOTIABLE RULES:
- If the user asks anything about S3 public access, you MUST call s3_public_buckets.
- If the user asks anything about an EC2 instance by IP address, you MUST call ec2_instance_by_ip.
- If a tool exists that can answer the question, you MUST use it. Do not give AWS Console/CLI instructions.

Style:
- Be concise.
- Give a clear conclusion first (Secure/Not secure/Needs review), then 2-5 bullets of evidence.
"""

# EC2 Security Analyzer
@tool("ec2_instance_by_ip")
def ec2_instance_by_ip(ip: str) -> str:
    """
    Use this tool whenever the user provides an IP address and asks about an EC2 instance.
    Returns instance id, instance type, whether it has a public IP, and whether any security group allows 0.0.0.0/0.
    """

    # Throttle calls because I'm not a millionaire :D
    ec2 = boto3.client(
        "ec2",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2}),
    )


    # Find network interface with that IP
    resp = ec2.describe_network_interfaces(
        Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}]
    )

    if not resp["NetworkInterfaces"]:
        # Try public IP
        resp = ec2.describe_network_interfaces(
            Filters=[{"Name": "association.public-ip", "Values": [ip]}]
        )

    if not resp["NetworkInterfaces"]:
        return f"No EC2 instance found with IP {ip}."

    eni = resp["NetworkInterfaces"][0]
    instance_id = eni["Attachment"]["InstanceId"]

    inst = ec2.describe_instances(InstanceIds=[instance_id])
    instance = inst["Reservations"][0]["Instances"][0]

    instance_type = instance["InstanceType"]
    public_ip = instance.get("PublicIpAddress", "None")
    subnet_id = instance["SubnetId"]
    sg_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]

    # Check security group exposure
    exposed_ports = []

    for sg_id in sg_ids:
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        for perm in sg["IpPermissions"]:
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    exposed_ports.append((from_port, to_port))

    lines = [
        f"Instance ID: {instance_id}",
        f"Instance type: {instance_type}",
        f"Public IP: {public_ip}",
        f"Subnet: {subnet_id}",
    ]

    def fmt_port(fp, tp):
        if fp is None or tp is None:
            return "all-ports"
        return str(fp) if fp == tp else f"{fp}-{tp}"

    if exposed_ports:
        ports_str = ", ".join(fmt_port(fp, tp) for fp, tp in exposed_ports)

        lines.append(f"⚠ Security groups allow 0.0.0.0/0 on ports: {ports_str}")
    else:
        lines.append("No security group rules allow 0.0.0.0/0.")

    # Tests if EC2 is exposed to the internet 
    internet_reachable = (public_ip != "None")
    ssh_world = any(p[0] == 22 or p[1] == 22 for p in exposed_ports if p[0] is not None)

    if internet_reachable and ssh_world:
        conclusion = "NOT SECURE (internet-exposed SSH)"
    elif internet_reachable and exposed_ports:
        conclusion = "NEEDS REVIEW (internet-exposed ports)"
    elif internet_reachable:
        conclusion = "NEEDS REVIEW (has public IP)"
    else:
        conclusion = "LIKELY PRIVATE (no public IP found)"

    lines.append(f"Conclusion: {conclusion}")


    return "\n".join(lines)

# User Permission Analyzer (Identity Center not AWS IAM - Identity Center is harder and better architecture which is why I selected it)
@tool("identity_center_admin_access")
def identity_center_admin_access(account_id: str = "") -> str:
    """
    Find Identity Center (SSO) users/groups with admin-like access in a given AWS account.
    Admin-like means:
      - Permission set has AWS managed policy 'AdministratorAccess', OR
      - Permission set name contains 'AdministratorAccess', OR
      - Inline policy allows Action='*' and Resource='*'
    If account_id is blank, uses current caller account.
    """

    # If caller didn't provide account_id, get it from STS
    if not account_id.strip():
        account_id = boto3.client("sts").get_caller_identity()["Account"]

    # In a real client build, this would be tailored to customer's resource-to-region usage
    region = os.getenv("AWS_REGION", "us-east-1")
    sso_admin = boto3.client("sso-admin", region_name=region)

    insts = sso_admin.list_instances().get("Instances", [])
    if not insts:
        return f"No IAM Identity Center instance found in region {region}. (Try setting AWS_REGION to your Identity Center region.)"

    instance_arn = insts[0]["InstanceArn"]
    identity_store_id = insts[0]["IdentityStoreId"]

    identitystore = boto3.client("identitystore", region_name=region)

    def is_admin_permission_set(permission_set_arn: str) -> (bool, list[str]):
        reasons = []

        ps = sso_admin.describe_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
        )["PermissionSet"]
        ps_name = ps.get("Name", "")

        if "AdministratorAccess" in ps_name:
            reasons.append("permission set name contains 'AdministratorAccess'")

        # Managed policies on permission set
        mp = sso_admin.list_managed_policies_in_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
        ).get("AttachedManagedPolicies", [])

        for p in mp:
            if p.get("Name") == "AdministratorAccess":
                reasons.append("attached managed policy: AdministratorAccess")

        # Inline policy on permission set
        try:
            inline = sso_admin.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
            ).get("InlinePolicy", "")

            # Wildcard permissions check
            if '"Action":"*"' in inline.replace(" ", "") and '"Resource":"*"' in inline.replace(" ", ""):
                reasons.append("inline policy allows wildcard * on *")
        except ClientError:
            pass

        return (len(reasons) > 0, reasons)

    def principal_name(principal_type: str, principal_id: str) -> str:
        try:
            if principal_type == "USER":
                u = identitystore.describe_user(IdentityStoreId=identity_store_id, UserId=principal_id)
                # prefer UserName, fallback to DisplayName/Id
                return u.get("UserName") or u.get("DisplayName") or principal_id
            if principal_type == "GROUP":
                g = identitystore.describe_group(IdentityStoreId=identity_store_id, GroupId=principal_id)
                return g.get("DisplayName") or principal_id
        except ClientError:
            return principal_id
        return principal_id

    # List permission sets
    perm_sets = []
    token = None
    while True:
        args = {"InstanceArn": instance_arn}
        if token:
            args["NextToken"] = token
        resp = sso_admin.list_permission_sets(**args)
        perm_sets.extend(resp.get("PermissionSets", []))
        token = resp.get("NextToken")
        if not token:
            break

    admin_sets = []
    for ps_arn in perm_sets:
        ok, reasons = is_admin_permission_set(ps_arn)
        if ok:
            ps = sso_admin.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)["PermissionSet"]
            admin_sets.append((ps_arn, ps.get("Name", ps_arn), reasons))

    if not admin_sets:
        return f"No admin-like permission sets detected for Identity Center in region {region}."

    # For each admin-like permission set, list users for this account
    lines = [f"Account: {account_id}", f"Identity Center region: {region}", "", "Admin-like access found via these permission sets:"]
    for _, name, reasons in admin_sets:
        lines.append(f"- {name} — " + "; ".join(reasons))

    lines.append("\nUsers (and service-linked roles) that have administrator capabilities in this account:")

    any_assignments = False
    for ps_arn, ps_name, _ in admin_sets:
        token = None
        assignments = []
        while True:
            args = {
                "InstanceArn": instance_arn,
                "AccountId": account_id,
                "PermissionSetArn": ps_arn,
            }
            if token:
                args["NextToken"] = token
            resp = sso_admin.list_account_assignments(**args)
            assignments.extend(resp.get("AccountAssignments", []))
            token = resp.get("NextToken")
            if not token:
                break

        if not assignments:
            continue

        any_assignments = True
        lines.append(f"\nPermission set: {ps_name}")
        for a in assignments:
            ptype = a["PrincipalType"]
            pid = a["PrincipalId"]
            pname = principal_name(ptype, pid)
            lines.append(f"- {ptype}: {pname}")

    if not any_assignments:
        lines.append("\n(None found in this account — admin permission sets exist, but may not be assigned here.)")

    return "\n".join(lines)


# S3 Security Analyzer
@tool("s3_public_buckets")
def s3_public_buckets() -> str:
    """
    Determine which S3 buckets are publicly accessible and explain why.
    Use this tool whenever the user asks about S3 public access.
    """

    s3 = boto3.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    public = []
    private = []
    review = []

    for name in buckets:
        reasons = []
        is_public = False
        pab_ok = True  # assume OK unless we see otherwise

        # 1) Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
                if pab.get(k) is False:
                    pab_ok = False
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                pab_ok = False
            else:
                pab_ok = False  # if we can't read it, treat as review

        if not pab_ok:
            reasons.append("public access protections are not fully enabled")

        # 2) Policy status
        try:
            ps = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
            if ps.get("IsPublic"):
                is_public = True
                reasons.append("bucket policy allows public access")
        except ClientError:
            pass

        # 3) ACL (legacy public grants)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                uri = (g.get("Grantee") or {}).get("URI", "")
                if uri.endswith("AllUsers"):
                    is_public = True
                    reasons.append("bucket ACL grants access to everyone (AllUsers)")
                if uri.endswith("AuthenticatedUsers"):
                    is_public = True
                    reasons.append("bucket ACL grants access to any AWS-authenticated user")
        except ClientError:
            pass

        # Classification
        if is_public:
            public.append((name, reasons))
        elif reasons:
            review.append((name, reasons))
        else:
            private.append(name)

    # Output
    lines = []
    if public:
        lines.append("**Public buckets (action needed):**")
        for name, rs in public:
            lines.append(f"- {name} — " + "; ".join(sorted(set(rs))))
    else:
        lines.append("**Public buckets (action needed):** none found.")

    if review:
        lines.append("\n**Buckets that look private but need review:**")
        for name, rs in review:
            lines.append(f"- {name} — " + "; ".join(sorted(set(rs))))
    else:
        lines.append("\n**Buckets that look private but need review:** none.")

    if private:
        lines.append("\n**Buckets that appear private:**")
        for name in private:
            lines.append(f"- {name}")
    else:
        lines.append("\n**Buckets that appear private:** none.")

    lines.append(
        "\nNote: Always confirm results with S3 console and IAM Access Analyzer!"
    )
    return "\n".join(lines)


def main():
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY not set (check your .env)")

    print("AWS Security Chatbot (minimal)")
    print("Type 'exit' to quit.\n")

    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    tools = [sts_whoami, s3_public_buckets, ec2_instance_by_ip, identity_center_admin_access]

    agent = create_agent(
        model=llm,
        tools=tools,
        system_prompt=SYSTEM,
    )

    while True:
        q = input("You: ").strip()
        if q.lower() in {"exit", "quit"}:
            break

        result = agent.invoke({"messages": [("user", q)]})
        print(result["messages"][-1].content)



if __name__ == "__main__":
    main()


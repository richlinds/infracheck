from infracheck.models import RuleResult

CATEGORY = "security"


def check_s3_public_access(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """S3 buckets should have public access fully blocked."""
    results = []

    for bucket in resources.get("aws_s3_bucket_public_access_block", []):
        is_blocked = (
            bucket.get("block_public_acls", False)
            and bucket.get("block_public_policy", False)
            and bucket.get("ignore_public_acls", False)
            and bucket.get("restrict_public_buckets", False)
        )
        results.append(
            RuleResult(
                rule_id="s3_public_access_blocked",
                category=CATEGORY,
                severity="high",
                passed=is_blocked,
                message="S3 bucket has all public access settings blocked"
                if is_blocked
                else "S3 bucket does not fully block public access - data may be publicly exposed",
                resource=bucket["_name"],
            )
        )

    return results


def check_rds_not_publicly_accessible(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should not be publicly accessible."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        is_public = instance.get("publicly_accessible", False)
        results.append(
            RuleResult(
                rule_id="rds_not_publicly_accessible",
                category=CATEGORY,
                severity="high",
                passed=not is_public,
                message="RDS instance is not publicly accessible"
                if not is_public
                else "RDS instance is publicly accessible - database should not be exposed"
                " to the internet",
                resource=instance["_name"],
            )
        )

    return results


def check_security_group_open_ingress(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Security groups should not allow unrestricted inbound traffic on sensitive ports."""
    results = []
    sensitive_ports = {22, 1433, 3306, 3389, 5432, 6379, 9200, 9300, 11211, 27017}

    for security_group in resources.get("aws_security_group", []):
        open_ports = []

        for ingress_rule in security_group.get("ingress", []):
            cidr_blocks = ingress_rule.get("cidr_blocks", [])
            if cidr_blocks and "0.0.0.0/0" in cidr_blocks:
                from_port = ingress_rule.get("from_port", 0)
                to_port = ingress_rule.get("to_port", 0)
                for port in sensitive_ports:
                    if from_port <= port <= to_port:
                        open_ports.append(port)

        has_open_ingress = len(open_ports) > 0
        results.append(
            RuleResult(
                rule_id="security_group_open_ingress",
                category=CATEGORY,
                severity="high",
                passed=not has_open_ingress,
                message="Security group has no open ingress on sensitive ports"
                if not has_open_ingress
                else f"Security group allows public ingress on sensitive ports: {open_ports}",
                resource=security_group["_name"],
            )
        )

    return results


def check_ec2_imdsv2_required(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """EC2 instances should require IMDSv2 to prevent SSRF-based metadata credential theft."""
    results = []

    for instance in resources.get("aws_instance", []):
        metadata_options = instance.get("metadata_options", {})
        # metadata_options may be a list due to hcl2 block parsing
        if isinstance(metadata_options, list):
            metadata_options = metadata_options[0] if metadata_options else {}
        http_tokens = metadata_options.get("http_tokens", "optional")
        requires_imdsv2 = http_tokens == "required"

        results.append(
            RuleResult(
                rule_id="ec2_imdsv2_required",
                category=CATEGORY,
                severity="high",
                passed=requires_imdsv2,
                message="EC2 instance requires IMDSv2"
                if requires_imdsv2
                else "EC2 instance does not require IMDSv2 - instance metadata is vulnerable"
                " to SSRF attacks",
                resource=instance["_name"],
            )
        )

    return results


def check_ec2_no_public_ip(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """EC2 instances should not have a public IP address assigned automatically."""
    results = []

    for instance in resources.get("aws_instance", []):
        has_public_ip = instance.get("associate_public_ip_address", False)

        results.append(
            RuleResult(
                rule_id="ec2_no_public_ip",
                category=CATEGORY,
                severity="medium",
                passed=not has_public_ip,
                message="EC2 instance does not have a public IP address"
                if not has_public_ip
                else "EC2 instance has a public IP address - prefer private subnets"
                " with a NAT gateway",
                resource=instance["_name"],
            )
        )

    return results


def check_s3_encryption(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """S3 buckets should have server-side encryption configured."""
    results = []

    for encryption_config in resources.get(
        "aws_s3_bucket_server_side_encryption_configuration", []
    ):
        rule_block = encryption_config.get("rule", [])
        has_encryption = bool(rule_block)

        results.append(
            RuleResult(
                rule_id="s3_encryption_enabled",
                category=CATEGORY,
                severity="medium",
                passed=has_encryption,
                message="S3 bucket has server-side encryption configured"
                if has_encryption
                else "S3 bucket does not have server-side encryption configured"
                " - data is stored unencrypted at rest",
                resource=encryption_config["_name"],
            )
        )

    return results


def check_rds_encryption(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have storage encryption enabled."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        is_encrypted = instance.get("storage_encrypted", False)

        results.append(
            RuleResult(
                rule_id="rds_storage_encrypted",
                category=CATEGORY,
                severity="high",
                passed=is_encrypted,
                message="RDS instance has storage encryption enabled"
                if is_encrypted
                else "RDS instance does not have storage encryption enabled"
                " - data at rest is unencrypted",
                resource=instance["_name"],
            )
        )

    return results


def check_lambda_no_secrets_in_env(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should not store secrets in plain-text environment variables."""
    results = []
    secret_patterns = {"PASSWORD", "PASSWD", "SECRET_KEY", "PRIVATE_KEY", "API_KEY"}

    for function in resources.get("aws_lambda_function", []):
        environment = function.get("environment", {})
        # environment may be a list due to hcl2 block parsing
        if isinstance(environment, list):
            environment = environment[0] if environment else {}
        env_vars = environment.get("variables", {}) if environment else {}
        if isinstance(env_vars, list):
            env_vars = env_vars[0] if env_vars else {}

        exposed_keys = [
            key
            for key in (env_vars or {})
            if any(pattern in key.upper() for pattern in secret_patterns)
        ]
        has_secrets = len(exposed_keys) > 0

        results.append(
            RuleResult(
                rule_id="lambda_no_secrets_in_env",
                category=CATEGORY,
                severity="medium",
                passed=not has_secrets,
                message="Lambda function has no obvious secrets in environment variables"
                if not has_secrets
                else f"Lambda function may have secrets in environment variables: {exposed_keys}",
                resource=function["_name"],
            )
        )

    return results

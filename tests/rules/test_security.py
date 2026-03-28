from infracheck.rules.security import (
    check_ec2_imdsv2_required,
    check_ec2_no_public_ip,
    check_rds_not_publicly_accessible,
    check_s3_public_access,
    check_security_group_open_ingress,
)


class TestS3PublicAccess:
    def test_passes_when_all_public_access_blocked(self):
        resources = {
            "aws_s3_bucket_public_access_block": [
                {
                    "_name": "my_bucket",
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                }
            ]
        }
        results = check_s3_public_access(resources)
        assert results[0].passed is True

    def test_fails_when_public_access_not_fully_blocked(self):
        resources = {
            "aws_s3_bucket_public_access_block": [
                {
                    "_name": "my_bucket",
                    "block_public_acls": True,
                    "block_public_policy": False,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                }
            ]
        }
        results = check_s3_public_access(resources)
        assert results[0].passed is False

    def test_fails_when_no_settings_defined(self):
        resources = {"aws_s3_bucket_public_access_block": [{"_name": "my_bucket"}]}
        results = check_s3_public_access(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_buckets(self):
        results = check_s3_public_access({})
        assert results == []


class TestRdsNotPubliclyAccessible:
    def test_passes_when_not_publicly_accessible(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "publicly_accessible": False}]}
        results = check_rds_not_publicly_accessible(resources)
        assert results[0].passed is True

    def test_passes_when_publicly_accessible_not_set(self):
        resources = {"aws_db_instance": [{"_name": "my_db"}]}
        results = check_rds_not_publicly_accessible(resources)
        assert results[0].passed is True

    def test_fails_when_publicly_accessible(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "publicly_accessible": True}]}
        results = check_rds_not_publicly_accessible(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_rds_not_publicly_accessible({})
        assert results == []


class TestSecurityGroupOpenIngress:
    def test_passes_when_no_open_ingress_on_sensitive_ports(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [{"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is True

    def test_fails_when_ssh_open_to_world(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is False

    def test_fails_when_postgres_open_to_world(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is False

    def test_passes_when_no_ingress_rules(self):
        resources = {"aws_security_group": [{"_name": "my_sg", "ingress": []}]}
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is True

    def test_fails_when_rdp_open_to_world(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [{"from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]}],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is False

    def test_fails_when_memcached_open_to_world(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [
                        {"from_port": 11211, "to_port": 11211, "cidr_blocks": ["0.0.0.0/0"]}
                    ],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is False

    def test_fails_when_elasticsearch_transport_open_to_world(self):
        resources = {
            "aws_security_group": [
                {
                    "_name": "my_sg",
                    "ingress": [{"from_port": 9300, "to_port": 9300, "cidr_blocks": ["0.0.0.0/0"]}],
                }
            ]
        }
        results = check_security_group_open_ingress(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_security_groups(self):
        results = check_security_group_open_ingress({})
        assert results == []


class TestEc2Imdsv2Required:
    def test_passes_when_imdsv2_required(self):
        resources = {
            "aws_instance": [{"_name": "my_ec2", "metadata_options": {"http_tokens": "required"}}]
        }
        results = check_ec2_imdsv2_required(resources)
        assert results[0].passed is True

    def test_passes_when_metadata_options_is_list(self):
        resources = {
            "aws_instance": [{"_name": "my_ec2", "metadata_options": [{"http_tokens": "required"}]}]
        }
        results = check_ec2_imdsv2_required(resources)
        assert results[0].passed is True

    def test_fails_when_http_tokens_is_optional(self):
        resources = {
            "aws_instance": [{"_name": "my_ec2", "metadata_options": {"http_tokens": "optional"}}]
        }
        results = check_ec2_imdsv2_required(resources)
        assert results[0].passed is False

    def test_fails_when_metadata_options_not_set(self):
        resources = {"aws_instance": [{"_name": "my_ec2"}]}
        results = check_ec2_imdsv2_required(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_ec2_imdsv2_required({})
        assert results == []


class TestEc2NoPublicIp:
    def test_passes_when_public_ip_not_set(self):
        resources = {"aws_instance": [{"_name": "my_ec2"}]}
        results = check_ec2_no_public_ip(resources)
        assert results[0].passed is True

    def test_passes_when_public_ip_disabled(self):
        resources = {"aws_instance": [{"_name": "my_ec2", "associate_public_ip_address": False}]}
        results = check_ec2_no_public_ip(resources)
        assert results[0].passed is True

    def test_fails_when_public_ip_enabled(self):
        resources = {"aws_instance": [{"_name": "my_ec2", "associate_public_ip_address": True}]}
        results = check_ec2_no_public_ip(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_ec2_no_public_ip({})
        assert results == []

# infracheck

![CI](https://github.com/richlinds/infracheck/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.14-blue)

Analyze software architecture for common design issues before they become production incidents.

infracheck reviews your infrastructure configuration and scores it across four categories:

- Fault Tolerance: DLQs, retries, Multi-AZ, backup policies, S3 versioning, ECS deployment health, SNS redrive policies
- Scalability: autoscaling, read replicas, ECS service scaling, SQS receive count limits
- Security: public access, open ingress, exposed databases, IMDSv2, EC2 public IPs, S3 and RDS encryption, Lambda secrets in env vars
- Observability: CloudWatch alarms, log groups, X-Ray tracing, log retention, ALB access logging, CloudTrail integration, VPC flow logs, ECS Container Insights, RDS enhanced monitoring, S3 access logging

## Usage

```bash
pip install infracheck
infracheck ./infra
```

### AI explanations

Pass `--explain` to have Claude generate a specific Terraform fix for each failing check:

```bash
infracheck ./infra --explain
```

Filter to a single category to focus the output:

```bash
infracheck ./infra --explain security
infracheck ./infra --explain fault_tolerance
infracheck ./infra --explain scalability
infracheck ./infra --explain observability
```

Requires an Anthropic API key - get one at [console.anthropic.com](https://console.anthropic.com):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### JSON output

Pass `--output json` (or `-o json`) for machine-readable output:

```bash
infracheck ./infra --output json
infracheck ./infra --output json --explain security | jq '.overall_score'
```

Status messages are written to stderr so they don't pollute the JSON stream.

### Configuration

| Environment variable    | Default           | Description                        |
|-------------------------|-------------------|------------------------------------|
| `ANTHROPIC_API_KEY`     | -                 | Required to use `--explain`        |
| `INFRACHECK_MODEL`      | `claude-opus-4-6` | Claude model used for explanations |
| `INFRACHECK_MAX_TOKENS` | `4096`            | Max tokens for explanation output  |
| `INFRACHECK_PATH`       | `./infra`         | Default path if none is specified  |

## Checks

### Fault Tolerance

| Rule ID | Severity | What is checked |
|---|---|---|
| `sqs_dlq_configured` | high | SQS queue has a dead-letter queue |
| `rds_multi_az_enabled` | high | RDS instance has Multi-AZ enabled |
| `rds_backup_retention` | medium | RDS backup retention is at least 7 days |
| `rds_deletion_protection` | medium | RDS instance has deletion protection enabled |
| `lambda_dlq_configured` | medium | Lambda function has a dead-letter queue |
| `dynamodb_pitr_enabled` | medium | DynamoDB table has point-in-time recovery enabled |
| `s3_versioning_enabled` | medium | S3 bucket has versioning enabled |
| `ecs_min_healthy_percent` | high | ECS service keeps at least 50% of tasks running during deployments |
| `sns_topic_dlq_configured` | medium | SNS topic has a redrive policy |

### Scalability

| Rule ID | Severity | What is checked |
|---|---|---|
| `autoscaling_configured` | medium | At least one autoscaling group is defined |
| `autoscaling_elb_health_check` | high | ASGs attached to a load balancer use ELB health checks |
| `lambda_reserved_concurrency` | high | Lambda function has a reserved concurrency limit |
| `rds_read_replicas` | low | RDS primary instance has at least one read replica |
| `elasticache_automatic_failover` | medium | ElastiCache replication group has automatic failover enabled |
| `elasticache_backup_retention` | medium | ElastiCache cluster retains snapshots for at least 1 day |
| `elasticache_cluster_size` | medium | ElastiCache replication group has at least 2 nodes |
| `load_balancer_cross_zone` | medium | NLB/GWLB has cross-zone load balancing enabled |
| `ecs_service_autoscaling` | medium | ECS service has Application Auto Scaling configured |
| `sqs_max_receive_count` | medium | SQS queue DLQ `maxReceiveCount` is at least 3 |

### Security

| Rule ID | Severity | What is checked |
|---|---|---|
| `s3_public_access_blocked` | high | S3 bucket has all public access settings blocked |
| `rds_not_publicly_accessible` | high | RDS instance is not publicly accessible |
| `security_group_open_ingress` | high | Security group has no open ingress on sensitive ports |
| `ec2_imdsv2_required` | high | EC2 instance requires IMDSv2 |
| `ec2_no_public_ip` | medium | EC2 instance has no public IP assigned |
| `s3_encryption_enabled` | medium | S3 bucket has server-side encryption configured |
| `rds_storage_encrypted` | high | RDS instance has storage encryption enabled |
| `lambda_no_secrets_in_env` | medium | Lambda env vars contain no obvious secret keys |

### Observability

| Rule ID | Severity | What is checked |
|---|---|---|
| `cloudwatch_alarms_exist` | medium | At least one CloudWatch alarm is defined |
| `lambda_log_group_exists` | medium | Each Lambda function has a CloudWatch log group |
| `lambda_xray_tracing` | medium | Lambda function has X-Ray tracing enabled |
| `log_group_retention_set` | medium | CloudWatch log groups have a retention period |
| `alb_access_logging_enabled` | medium | ALB has access logging enabled |
| `cloudtrail_cloudwatch_integration` | high | CloudTrail trail is integrated with CloudWatch Logs |
| `vpc_flow_logs_enabled` | high | Each VPC has flow logs enabled |
| `ecs_container_insights_enabled` | medium | ECS cluster has Container Insights enabled |
| `rds_enhanced_monitoring` | low | RDS instance has enhanced monitoring enabled |
| `s3_server_access_logging_enabled` | low | S3 bucket has server access logging enabled |

## Supported inputs

- AWS Terraform resources - supported
- GCP Terraform resources - planned
- draw.io diagrams - planned
- Architecture images - planned

## Why not just use Checkov or tfsec?

Checkov and tfsec are great tools but they focus almost entirely on security misconfigurations. infracheck is different in a few ways:

- **Broader scope** - covers fault tolerance, scalability, and observability, not just security
- **Architecture scoring** - gives each category a score so you can track improvement over time
- **AI explanations** - uses Claude to explain why a check failed and how to fix it, in plain language
- **Simpler output** - designed to be readable by developers, not just security engineers

## Status

Under active development.
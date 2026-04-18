# infracheck

![CI](https://github.com/richlinds/infracheck/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.14-blue)

Analyze software architecture for common design issues before they become production incidents.

infracheck reviews your infrastructure configuration and scores it across four categories:

- Fault Tolerance: DLQs, retries, Multi-AZ, backup policies
- Scalability: autoscaling, read replicas, bottlenecks
- Security: public access, open ingress, exposed databases, IMDSv2, EC2 public IPs
- Observability: CloudWatch alarms, log groups, X-Ray tracing, log retention, ALB access logging, CloudTrail integration, VPC flow logs

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

Requires an Anthropic API key — get one at [console.anthropic.com](https://console.anthropic.com):

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
| `ANTHROPIC_API_KEY`     | —                 | Required to use `--explain`        |
| `INFRACHECK_MODEL`      | `claude-opus-4-6` | Claude model used for explanations |
| `INFRACHECK_MAX_TOKENS` | `4096`            | Max tokens for explanation output  |
| `INFRACHECK_PATH`       | `./infra`         | Default path if none is specified  |

## Supported inputs

- AWS Terraform resources - supported
- GCP Terraform resources - planned
- draw.io diagrams - planned
- Architecture images - planned

## Why not just use Checkov or tfsec?

Checkov and tfsec are great tools but they focus almost entirely on security misconfigurations. infracheck is different in a few ways:

- **Broader scope** — covers fault tolerance, scalability, and observability, not just security
- **Architecture scoring** — gives each category a score so you can track improvement over time
- **AI explanations** — uses Claude to explain why a check failed and how to fix it, in plain language
- **Simpler output** — designed to be readable by developers, not just security engineers

## Status

Under active development.
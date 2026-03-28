# infracheck

Analyze software architecture for common design issues before they become production incidents.

infracheck reviews your infrastructure configuration and scores it across four categories:

- Fault Tolerance: DLQs, retries, Multi-AZ, backup policies
- Scalability: autoscaling, read replicas, bottlenecks
- Security: public access, open ingress, exposed databases
- Observability: CloudWatch alarms, log groups, X-Ray tracing, log retention, ALB access logging, CloudTrail integration, VPC flow logs

## Usage

```bash
pip install infracheck
infracheck analyze ./infra
```

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

Under active development — CLI not yet available.
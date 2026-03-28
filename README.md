# infracheck

Analyze software architecture for common design issues before they become production incidents.

infracheck reviews your infrastructure configuration and scores it across four categories:

- Fault Tolerance: DLQs, retries, Multi-AZ, backup policies
- Scalability: autoscaling, read replicas, bottlenecks
- Security: public access, open ingress, exposed databases
- Observability: CloudWatch alarms, log groups, tracing

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

## Status

Under active development — CLI not yet available.
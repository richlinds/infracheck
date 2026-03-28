from pathlib import Path

import hcl2


def parse_directory(path: str) -> dict[str, list[dict]]:
    """Parse all .tf files in a directory and return resources grouped by type."""
    resources: dict[str, list[dict]] = {}

    # Find all .tf files recursively under the given path
    tf_files = list(Path(path).rglob("*.tf"))
    if not tf_files:
        return resources

    for tf_file in tf_files:
        try:
            with open(tf_file) as file:
                parsed = hcl2.load(file)
        except Exception:
            # Skip files that can't be parsed rather than crashing the whole run
            continue

        # Each "resource" block in HCL becomes a list of dicts, one per block
        for resource_block in parsed.get("resource", []):
            # resource_type is e.g. "aws_sqs_queue", instances is a dict of named resources
            for resource_type, instances in resource_block.items():
                for resource_name, config in instances.items():
                    # hcl2 wraps block bodies in a list, so unwrap it
                    if isinstance(config, list):
                        config = config[0]
                    # Store the Terraform resource label as _name so we can reference it in findings
                    entry = {"_name": resource_name, **config}
                    resources.setdefault(resource_type, []).append(entry)

    return resources

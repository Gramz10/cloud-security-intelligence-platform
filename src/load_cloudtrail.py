import json


def load_cloudtrail(file_path: str) -> list[dict]:
    """Load and validate CloudTrail records from a local JSON file."""
    try: 
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

    except json.JSONDecodeError:
        raise ValueError("Unable to parse CloudTrail JSON.")

    if not isinstance(data, dict):
        raise ValueError("CloudTrail JSON must contain a dictionary.")

    if "Records" not in data:
        raise ValueError("Missing Records field")

    records = data["Records"]

    if not isinstance(records, list):
        raise ValueError("Records must be a list.")

    if not records:
        raise ValueError("No security events found.")

    for event in records:

        if not isinstance(event, dict):
            raise ValueError("Invalid record type.")

    return records

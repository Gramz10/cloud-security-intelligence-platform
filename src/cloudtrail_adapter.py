from src.security_event import validate_source_ip, validate_timestamp, validate_nonempty_string, create_security_event
from datetime import datetime, timezone

def classify_source_ip(source_ip):
    """Classify a CloudTrail source address."""
    
    if not source_ip:
        return "missing"
    if validate_source_ip(source_ip):
        return "ip_address"
    return "non_ip"

def normalize_source_ip(record: dict) -> dict:
    """Normalize the source address while preserving its original value."""
    
    raw_ip = record.get("sourceIPAddress")
    source_ip_type = classify_source_ip(raw_ip)
    
    if source_ip_type == "ip_address":
        normalized_ip = raw_ip
        
    else:
        normalized_ip = None    
        
    return {
            "source_ip_raw": raw_ip,
            "source_ip_type": source_ip_type,
            "source_ip": normalized_ip 
    }

def normalize_timestamp(timestamp: str) -> str:
    """Convert a timezone-aware ISO timestamp into a UTC string."""

    if not validate_timestamp(timestamp):
        raise ValueError("invalid or timezone-naive timestamp")
    
    parsed_timestamp = datetime.fromisoformat(timestamp)
    utc_timestamp = parsed_timestamp.astimezone(timezone.utc)
    
    return utc_timestamp.isoformat()


def adapt_cloudtrail_event(record: dict) -> dict:
    """Convert one CloudTrail record into our internal event format."""
    if not isinstance(record, dict):
        raise ValueError("CloudTrail record must be a dictionary.")

    raw_timestamp = record.get("eventTime")
    normalized_timestamp = normalize_timestamp(raw_timestamp)

    ip_metadata = normalize_source_ip(record)

    user = extract_user_identity(record)

    action = record.get("eventName")

    region = record.get("awsRegion")

    resource = extract_resource(record)

    event_data = {
    "timestamp": normalized_timestamp,
    "source_ip": ip_metadata["source_ip"],
    "user": user,
    "action": action,
    "region": region,
    "resource": resource
    }

    security_event = create_security_event(event_data)

    adapter_output = {
    "timestamp": normalized_timestamp,
    "user": user,
    "action": action,
    "region": region,
    "resource": resource,
    "security_event": security_event,
    "ip_metadata": ip_metadata,
    "raw_record": record.copy()
    }   

    return adapter_output

def extract_user_identity(record: dict) -> str | None:
    """Extract an available identity from a CloudTrail record."""
    identity = record.get("userIdentity")
   
    if not isinstance(identity, dict):
        return None

    user_name = identity.get("userName")

    if user_name:
        return user_name
    
    return identity.get("arn")

def extract_resource(record: dict) -> str | None:
    """Extract the first available CloudTrail resource name."""
    resources = record.get("resources")

    if not resources:
        return None

    if not isinstance(resources, list):
        return None
        
    first_resource = resources[0]

    if not isinstance(first_resource, dict):
        return None

    resource_name = first_resource.get("resourceName")
    
    if validate_nonempty_string(resource_name):
        return resource_name

    return None


if __name__ == "__main__":

    sample_record = {
    "eventTime": "2026-11-03T14:32:00Z",
    "eventName": "PutObject",
    "sourceIPAddress": "AWS Internal",
    "awsRegion": "us-east-1",
    "userIdentity": {"userName": "admin"},
    "resources": [
        {"resourceName": "analytics-logs"}
    ]
}
    result = adapt_cloudtrail_event(sample_record)

    print("SecurityEvent:", result["security_event"])
    print("IP metadata:", result["ip_metadata"])
    print("Action:", result["action"])
    print("Raw record:", result["raw_record"])
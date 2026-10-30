import json
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

sample_json = '''
{
    "timestamp": "2026-10-24T14:32:00Z",
    "source_ip": "203.0.113.42",
    "user": "admin",
    "action": "ConsoleLogin",
    "resource": "aws-production-server",
    "region": "us-east-1"
}
'''

sample_dict = json.loads(sample_json)

@dataclass
class SecurityEvent:
    timestamp: str
    source_ip: str
    user: str
    action: str
    resource: str
    region: str


event = SecurityEvent(
    timestamp=sample_dict['timestamp'],
    source_ip=sample_dict['source_ip'],
    user=sample_dict['user'],
    action=sample_dict['action'],
    resource=sample_dict['resource'],
    region=sample_dict['region']
)


def validate_source_ip(source_ip: str) -> bool:
    """Check whether a source IP value has the expected data type and is a valid IPv4 or IPv6 address."""
    
    if not isinstance(source_ip, str):
        return False

    try:
        ipaddress.ip_address(source_ip)
        return True
    
    except ValueError:
        return False


def validate_nonempty_string(value: str) -> bool:
    """Return True if the value is a string containing non-whitespace text."""

    if not isinstance(value, str):
        return False

    return bool(value.strip())

def validate_timestamp(timestamp: str) -> bool:
    """Check that timestamp is a nonempty string. Also parse the timestamp."""

    if not validate_nonempty_string(timestamp):
        return False

    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)

        if parsed_timestamp.tzinfo is None:

            logger.warning("Timestamp is missing timezone information.")
            return False

        elif parsed_timestamp.tzinfo is not None:
            return True

    except ValueError:

        logger.warning("Timestamp cannot be parsed.")

        return False

def validate_security_event(event_data: dict) -> bool:
    """Check whether a security event contains all required fields."""

    if not isinstance(event_data, dict):
        return False

    required_fields = [
        "timestamp",
        "source_ip",
        "user",
        "action",
        "resource",
        "region"
    ]

    for field in required_fields:
        if field not in event_data:

            logger.warning("Missing event_data field: %s", field)

            return False

    if not validate_timestamp(event_data["timestamp"]):

        logger.warning("Invalid event timestamp")
        
        return False

    if not validate_source_ip(event_data["source_ip"]):
        return False

    string_fields = [
        "user",
        "action",
        "resource",
        "region"
    ]

    for field in string_fields:
        if not validate_nonempty_string(event_data[field]):
            return False

    return True

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
        datefmt="%m/%d/%Y %I:%M:%S %p"
    )
    incomplete_event = {
    "timestamp": "not-a-date",
    "source_ip": "203.0.113.42",
    "user": "admin",
    "action": "ConsoleLogin",
    "resource": "aws-server-01",
    "region": "Northwest"
    }

#print(validate_security_event(incomplete_event))
print(validate_timestamp("2026-10-24T14:32:00Z"))
print(validate_timestamp("2026-10-24T14:32:00"))
print(validate_timestamp("not-a-date"))
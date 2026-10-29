import json
import ipaddress
from dataclasses import dataclass

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


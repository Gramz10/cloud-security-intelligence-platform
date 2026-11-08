import pytest

from src.cloudtrail_adapter import adapt_cloudtrail_event
from src.security_event import SecurityEvent

def test_valid_cloudtrail_event():
    record = {
        "eventTime": "2026-11-03T14:32:00Z",
        "eventName": "PutObject",
        "sourceIPAddress": "203.0.113.42",
        "awsRegion": "us-east-1",
        "userIdentity": {"userName": "admin"},
        "resources": [{"resourceName": "analytics-logs"}]
    }

    result = adapt_cloudtrail_event(record)

    assert isinstance(result["security_event"], SecurityEvent)
    assert result["timestamp"] == "2026-11-03T14:32:00+00:00"
    assert result["resource"] == "analytics-logs"

def test_cloudtrail_event_with_non_ip_source():
    record = {
        "eventTime": "2026-11-03T14:32:00Z",
        "eventName": "PutObject",
        "sourceIPAddress": "AWS Internal",
        "awsRegion": "us-east-1",
        "userIdentity": {"userName": "admin"},
        "resources": [{"resourceName": "analytics-logs"}]
    }

    result = adapt_cloudtrail_event(record)

    assert result["security_event"] is None
    assert result["ip_metadata"]["source_ip_type"] == "non_ip"
    assert result["ip_metadata"]["source_ip_raw"] == "AWS Internal"

def test_cloudtrail_event_with_invalid_timestamp():
    record = {
        "eventTime": "not-a-timestamp",
        "eventName": "PutObject",
        "sourceIPAddress": "203.0.113.42",
        "awsRegion": "us-east-1",
        "userIdentity": {"userName": "admin"},
        "resources": [{"resourceName": "analytics-logs"}]
    }

    with pytest.raises(ValueError):
        adapt_cloudtrail_event(record)
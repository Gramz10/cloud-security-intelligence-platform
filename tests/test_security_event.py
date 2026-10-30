from src.security_event import (
    SecurityEvent,
    validate_security_event,
    create_security_event,
)

def test_create_valid_security_event():
    
    #Arrange
    valid_event = {
        "timestamp": "2026-10-24T14:32:00Z",
        "source_ip": "203.0.113.42",
        "user": "admin",
        "action": "ConsoleLogin",
        "resource": "aws-server-01",
        "region": "us-east-1"
    }

    #Act
    result = create_security_event(valid_event)
    

    #Assert
    assert isinstance(result, SecurityEvent)


def test_invalid_security_event():

    #Arrange
    invalid_event = {
        "timestamp": "2026-10-24T14:32:00Z",
        "source_ip": "999.999.999.999",
        "user": "admin",
        "action": "ConsoleLogin",
        "resource": "aws-server-01",
        "region": "us-east-1"
    }

    #Act
    result = create_security_event(invalid_event)

    #Assert
    assert result is None


def test_missing_required_field():

    #Arrange
    invalid_event = {
        "timestamp": "2026-10-24T14:32:00Z",
        "source_ip": "203.0.113.42",
        "user": "admin",
        "action": "ConsoleLogin",
        "resource": "aws-server-01"
    }

    #Act
    result = validate_security_event(invalid_event)

    #Assert
    assert result is False

def test_none_security_event():

    #Arrange
    invalid_event = None

    #Act
    result = validate_security_event(invalid_event)

    #Assert
    assert result is False

def test_nonempty_string_security_event():
    
    #Arrange
    test_event = {
        "timestamp": "2026-10-24T14:32:00Z",
        "source_ip": "203.0.113.42",
        "user": "    ",
        "action": "ConsoleLogin",
        "resource": "aws-server-01",
        "region": "us-east-1"
    }

    #Act
    result = validate_security_event(test_event)
    

    #Assert
    assert result is False
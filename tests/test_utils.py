import pytest
from src.utils import format_resource_name

def test_format_resource_name():
    
    #Arrange
    resource_name = "aws-server-01"
    expected_result = "AWS-SERVER-01"

    #Act
    actual_result = format_resource_name(resource_name)

    #Assert
    assert expected_result == actual_result


def test_format_resource_name_empty():
    
    #Arrange
    resource_name = ""
    expected_result = ""

    #Act
    actual_result = format_resource_name(resource_name)

    #Assert
    assert expected_result == actual_result


def test_format_resource_name_invalid():
    
    #Arrange
    resource_name = None

    #Act / Assert
    with pytest.raises(AttributeError):
        format_resource_name(resource_name)
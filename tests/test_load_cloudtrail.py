import pytest

from src.load_cloudtrail import load_cloudtrail


def test_malformed_json(tmp_path):

    # Arrange
    file_path = tmp_path / "malformed.json"
    file_path.write_text('{"Records": [}', encoding="utf-8")

    # Act and Assert
    with pytest.raises(ValueError):
        load_cloudtrail(file_path)


def test_missing_records(tmp_path):
    
    # Arrange
    file_path = tmp_path / "missing_records.json"
    file_path.write_text('{"Account": 123456789012}', encoding="utf-8")

    # Act & Assert
    with pytest.raises(ValueError, match="Missing Records field"):
        load_cloudtrail(file_path)


def test_invalid_record_type(tmp_path):
    
    # Arrange
    file_path = tmp_path / "invalid_record.json"
    file_path.write_text('{"Records": [{"eventName": "ConsoleLogin"}, "invalid_record"]}', encoding="utf-8")

    # Act & Assert
    with pytest.raises(ValueError, match="Invalid record type"):
        load_cloudtrail(file_path)

def test_valid_cloudtrail(tmp_path):
    
    # Arrange
    valid_json = '{"Records": [{"eventName": "ConsoleLogin"}, {"eventName": "CreateUser"}]}'
    file_path = tmp_path / "valid_json.json"
    file_path.write_text(valid_json, encoding="utf-8")

    # Act
    result = load_cloudtrail(file_path)

    #Assert
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[1]["eventName"] == "CreateUser"


import random, json
from datetime import datetime, timedelta, timezone

def generate_synthetic_events(count: int = 100) -> list[dict]:
    """Generate reproducible synthetic CloudTrail-style events."""

    duplicate_count = min(5, count // 2)

    rng = random.Random(42)

    users = ["admin", "analyst", "developer", "service-user"]

    actions = ["ConsoleLogin", "GetObject", "PutObject"]

    regions = ["us-east-1", "us-west-2", "eu-west-1"]

    source_ips = [
        "203.0.113.42",
        "198.51.100.5",
        "192.0.2.15"
    ]

    events = []

    start_date = datetime(2026, 11, 10, tzinfo=timezone.utc)

    for _ in range(count - duplicate_count):
        selected_user = rng.choice(users)
        selected_action = rng.choice(actions)
        selected_region = rng.choice(regions)
        selected_source_ip = rng.choice(source_ips)

        
        random_day = rng.randint(0, 4)
        random_hour = rng.randint(0, 23)
    
        event_time = start_date + timedelta(
            days=random_day,
            hours=random_hour
        )

        event_record = {
            "eventTime": event_time.isoformat(),
            "eventName": selected_action,
            "sourceIPAddress": selected_source_ip,
            "awsRegion": selected_region,
            "userIdentity":{
                "userName": selected_user
            },
            "resources": [
                {"resourceName": "analytics-logs"}
                ]
            }

        if rng.random() < 0.10:
            event_record.pop("sourceIPAddress", None)

        if rng.random() <0.15:
            event_record["errorCode"] = "AccessDenied"
            event_record["errorMessage"] = "User is not authorized to perform this action"

        events.append(event_record)

    for i in range(duplicate_count):
        original_event = events[i]

        copy_original_event = original_event.copy()

        events.append(copy_original_event)
    
    return events


if __name__ == "__main__":
    events = generate_synthetic_events(100)

    fixture = {
        "_metadata": {
            "synthetic": True,
            "description": "Synthetic CloudTrail-style events for learning and testing",
            "seed": 42
        },
        "Records": events
    }

    with open("data/synthetic_cloudtrail.json", "w", encoding="utf-8") as file:
        json.dump(fixture, file, indent=2)

    from src.load_cloudtrail import load_cloudtrail

    records = load_cloudtrail("data/synthetic_cloudtrail.json")

    print("Loaded records:", len(records))
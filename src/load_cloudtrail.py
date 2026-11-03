import json

with open("data/sample_cloudtrail.json", "r") as file:
    data = json.load(file)

''' Checking the different data types at each level of the sample_cloudtrail.json
print(type(data))
print(type(data["Records"]))
print(type(data["Records"][0]))
'''

first_event = data["Records"][0]
print(first_event)

print(type(first_event["userIdentity"]))

user_identity = first_event["userIdentity"]
user_name = user_identity["userName"]
print(user_name)

field_map = {
    "timestamp": first_event["eventTime"],
    "action": first_event["eventName"],
    "source_ip": first_event["sourceIPAddress"],
    "region": first_event["awsRegion"],
    "user": first_event["userIdentity"]["userName"]
}

print(field_map)
### convert caldera event json file to normalised json file

import json
from config import CALDERA, OUTPUT

## HOST to IP mapping
HOST_TO_IP ={
"src":"192.168.2.36",
"desktop-0a76r29": "10.0.2.20",
"ubuntu-vb": "10.0.2.15"
}

## tactic -> category
TACTIC_TO_CATEGORY = {
    "reconnaissance": "reconnaissance",
    "resource-development": "reconnaissance",

    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",

    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",

    "discovery": "discovery",
    "lateral-movement": "lateral_movement",

    "collection": "collection",
    "command-and-control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "execution"
}

def parse_caldera_flat(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    events = []

    for item in data:
        event = {
            "event_id": item.get("ability_metadata", {}).get("ability_id"),

            "timestamp": item.get("finished_timestamp"),

            "host": item.get("agent_metadata", {}).get("host"),
            "agent_id": item.get("agent_metadata", {}).get("paw"),
            "username": item.get("agent_metadata", {}).get("username"),
            "platform": item.get("platform"),

            "executor": item.get("executor"),
            "command": item.get("command"),

            "stdout": "",   # not present in your data
            "stderr": "",   #  not present
            "exit_code": item.get("status", -1),
            "status": "success" if item.get("status") == 0 else "failed",

            "technique_id": item.get("attack_metadata", {}).get("technique_id"),
            "technique_name": item.get("attack_metadata", {}).get("technique_name"),
            "tactic": item.get("attack_metadata", {}).get("tactic"),

            "operation_name": item.get("operation_metadata", {}).get("operation_name"),
            "adversary": item.get("operation_metadata", {}).get("operation_adversary"),

            "source": "caldera"
        }

        events.append(event)

    return events

def normalize_event(e):
    e["stdout"] = (e["stdout"] or "").strip()
    e["stderr"] = (e["stderr"] or "").strip()

    # Normalize status
    if e["exit_code"] == 0:
        e["status"] = "success"
    else:
        e["status"] = "failed"

    e["activity_type"] = "host"    

    return e

## classification or enrichment
def classify_event(e):
    tactic = (e["tactic"] or "").lower()
    host = (e["host"] or "").lower()
    e["category"] = TACTIC_TO_CATEGORY.get(tactic,"unknown")
    e["src_ip"] = HOST_TO_IP.get("src")
    e["dst_ip"] = HOST_TO_IP.get(host)

    return e

#
def save_events(events, path):
    with open(path, "w") as f:
        json.dump(events, f, indent=2)


### 
events = parse_caldera_flat(CALDERA.get("raw_event_json"))
events = [normalize_event(e) for e in events]
events = [classify_event(e) for e in events]
print(events[0])
print (len(events))
save_events(events=events, path=OUTPUT.get("caldera_events"))


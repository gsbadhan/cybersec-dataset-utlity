import os
import yaml
import config
import pandas as pd
import json

MITRE_TACTIC_TECHNIQUE_GROUP_CSV = 'mitre_tactic_technique_group.csv'

# {'tactic_id': 'TA0002|TA0003|TA0004', 'technique_id': 'T1053', 'sub_technique_id': 'T1053.005', 'command': 'SCHTASKS /Create /SC ONCE /TN spawn /TR #{task_command} /ST #{time}\n', 'platform': 'command_prompt', 'description': 'Upon successful execution, cmd.exe will create a scheduled task to spawn cmd.exe at 20:10.\n', 'source': 'atomicred'}
def saveAtomicRed(events):
    with open(config.OUTPUT.get("atomic_red_events"), "w") as f:
        json.dump(events, f, indent=2)


def get_tactics(technique_id):
    df = pd.read_csv(MITRE_TACTIC_TECHNIQUE_GROUP_CSV)
    tactic_ids = ', '.join(df.query(f"technique_id == '{technique_id}'")['tactic_id'])
    tactic_names = ', '.join(df.query(f"technique_id == '{technique_id}'")['tactic_name'])
    return tactic_ids,tactic_names


def parse_atomic(base_path):
    dataset = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if not file.endswith(".yaml"):
                continue

            path = os.path.join(root, file)

            with open(path) as f:
                data = yaml.safe_load(f)

            technique_id = ""
            sub_technique_id = ""
            tactic_id = ""
            tactic_name = ""
            attack_technique = data.get("attack_technique")
            if attack_technique is not None:
                technique = data.get("attack_technique").split(".")
                if (len(technique) == 1):
                    technique_id = technique[0]
                    tactics = get_tactics(technique_id)
                    tactic_id = tactics[0]
                    tactic_name = tactics[1]
                elif (len(technique) == 2):
                    technique_id = technique[0]
                    sub_technique_id = attack_technique
                    tactics = get_tactics(technique_id)
                    tactic_id = tactics[0]
                    tactic_name = tactics[1]

            for test in data.get("atomic_tests", []):
                executor = test.get("executor", {})
                command = executor.get("command")

                if not command:
                    continue

                dataset.append({
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "technique_id": technique_id,
                    "sub_technique_id": sub_technique_id,
                    "command": command,
                    "platform": executor.get("name"),
                    "description": test.get("description"),
                    "source": "atomicred"
                })

    return dataset

records = parse_atomic(config.ATOMIC.get("atomics_path"))
print(records[1])
saveAtomicRed(records)


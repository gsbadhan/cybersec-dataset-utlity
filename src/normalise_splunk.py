import yaml
import config
import glob
import json

def parse_detection(path):
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    tags = data.get("tags", {})

    return {
        "rule_name": data.get("name"),
        "description": data.get("description"),
        "search_query": data.get("search"),
        "mitre_technique_ids": tags.get("mitre_attack_id", []),
        "analytic_story": tags.get("analytic_story", []),
        "security_domain": tags.get("security_domain"),
        "references": data.get("references", []),
        "activity_type": "detection_rule",
        "asset_type": data.get("asset_type"),
        "source": "splunk"
    }

def append_json(file_path, record):
    with open(file_path, 'a') as f:
        f.write(json.dumps(record) + '\n')

def parse_all():
    folders=config.SPLUNK_SECURITY_CONTENT.get("detections_folders")
    base_path=config.SPLUNK_SECURITY_CONTENT.get("detections_path")
    output_file=config.OUTPUT.get("splunk_detection_events")

    for folder in folders:
        folder_path = f"{base_path}/{folder}"
        print(folder_path)
        yaml_files = glob.glob(f"{folder_path}/*.yml")
        print(yaml_files)
        for file in yaml_files:
            print(file)
            record = parse_detection(file)
            append_json(file_path=output_file, record=record)

#### run
parse_all()
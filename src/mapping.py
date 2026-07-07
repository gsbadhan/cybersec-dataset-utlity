from config import CALDERA, OUTPUT
import csv
from collections import defaultdict

## collections
MITRE_TACTICNAME_TO_TACTICID = defaultdict(set)
MITRE_TACTICID_TO_TACTICNAME = defaultdict(set)
MITRE_TECHNIQUENAME_TO_TECHNIQUEID = defaultdict(set)
MITRE_TECHNIQUEID_TO_TECHNIQUENAME = defaultdict(set)

## HOST to IP mapping
HOST_TO_IP ={
"src":"192.168.2.36",
"DESKTOP-0A76R29": "10.0.2.20",
"ubuntu-vb": "10.0.2.15"
}

LOG_SOURCES ={
    "CALDERA": "caldera"
}

ASSET_TYPE= ["workstation", "web_server", "standalone"]

PRIORITY= ["high", "medium", "low"]

TRAFFIC_DIR= ["egress", "ingress"]


""" tactic_name -> tactic_id """
""" tactic_id -> tactic_name """
""" technique_id -> technique_name """
""" technique_name -> technique_id """
def mapping_tactic_name_to_tactic_id():
    mitre_file= "/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/mitre_tactic_technique.csv"
    with open(mitre_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            tactic_name= row['tactic_name']
            tactic_id= row['tactic_id']
            MITRE_TACTICNAME_TO_TACTICID[tactic_name]= tactic_id
            MITRE_TACTICID_TO_TACTICNAME[tactic_id]= tactic_name
            technique_id= row['technique_id']
            technique_name= row['technique_name']
            MITRE_TECHNIQUEID_TO_TECHNIQUENAME[technique_id]= technique_name
            MITRE_TECHNIQUENAME_TO_TECHNIQUEID[technique_name]= technique_id


def extract_process_name(cmd: str) -> str:
    """Extract process name - just split and take first part."""
    if not cmd:
        return ""
    # Get first word before any special characters
    first_part = cmd.strip().split()[0] if cmd.strip().split() else ""
    # Remove quotes and path
    return first_part.strip('"\'/\\')[:15]


def init_mappings():
    mapping_tactic_name_to_tactic_id()


###
init_mappings()
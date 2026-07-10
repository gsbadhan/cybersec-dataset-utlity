import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LANGSMITH_API_KEY = os.getenv("LANGSMITH_API_KEY")
LANGSMITH_PROJECT = os.getenv("LANGSMITH_PROJECT")
LANGSMITH_TRACING = os.getenv("LANGSMITH_TRACING")


# =========================
# DATASET ROOT (portable)
# =========================
BASE_DIR = os.getenv(
    "DATASET_DIR",
    os.path.expanduser("~/Downloads/cybersec-dataset")
)

CALDERA_BASE_DIR = os.getenv(
    "CALDERA_DIR",
    os.path.expanduser("~/Downloads/cybersec-dataset/caldera-events")
)

ATOMIC_BASE_DIR = os.getenv(
    "ATOMIC_DIR",
    os.path.expanduser("~")
)


# =========================
# ATOMIC RED TEAM
# =========================
ATOMIC = {
    "atomics_path": os.path.join(ATOMIC_BASE_DIR, "AtomicRedTeam", "atomics")
}


# =========================
# SPLUNK SECURITY CONTENT
# =========================
SPLUNK = os.getenv(
    "SPLUNK_DIR",
    os.path.expanduser("~/Downloads/cybersec-dataset/security_content")
)

# =========================
# CIC IDS 2017
# =========================
CIC = {
    "raw_csv_path": os.path.join(BASE_DIR, "cic/2017/ids/MachineLearningCVE"),
    "all_ml_cve_csv": os.path.join(BASE_DIR, "cic/2017/ids/cic_machine_learning_cve_merged.csv")
}

# =========================
# DARPA 1998
# =========================
DARPA_1998 = {
    "base_path": os.path.join(BASE_DIR, "darpa/1998/week1"),
    "days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
    "files": {
        "attacks": "attacks.memo",
        "network": "tcpdump.log",
        "host": "pascal.log"
    }
}

# =========================
# DARPA 1999
# =========================
DARPA_1999 = {
    "base_path": os.path.join(BASE_DIR, "darpa/1999/week1"),
    "days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
    "files": {
        "inside_network": "inside.tcpdump.log",
        "outside_network": "outside.tcpdump.log",
        "host": "pascal.bsm.log"
    }
}

# =========================
# SNORT RULES
# =========================
SNORT = {
    "rules": os.path.join(BASE_DIR, "snort/v3_0/snort3-community-rules/snort3-community.rules"),
    "sid_map": os.path.join(BASE_DIR, "snort/v3_0/snort3-community-rules/sid-msg.map")
}

# =========================
# CALDERA
# =========================
CALDERA = {
    "raw_event_json": os.path.join(CALDERA_BASE_DIR,"raw_events.json")
}

# =========================
# Splunk security content
# =========================
SPLUNK_SECURITY_CONTENT = {
    "detections_path": os.path.join(SPLUNK,"detections"),
    "detections_folders": ["application", "cloud", "endpoint", "network", "web"]
}

# =========================
# UNSW-NB15
# =========================
UNSW = {
    "csv_files_1": os.path.join(BASE_DIR, "unsw-nb15/csv_files/UNSW-NB15_1.csv"),
    "csv_files_2": os.path.join(BASE_DIR, "unsw-nb15/csv_files/UNSW-NB15_2.csv"),
    "csv_files_3": os.path.join(BASE_DIR, "unsw-nb15/csv_files/UNSW-NB15_3.csv"),
    "csv_files_4": os.path.join(BASE_DIR, "unsw-nb15/csv_files/UNSW-NB15_4.csv"),
    "merged_ml_csv": os.path.join(BASE_DIR, "unsw-nb15/csv_files/unsw_machine_learning_cve_merged.csv")
}

# =========================
# OUTPUT PATHS
# =========================
OUTPUT = {
    "processed_dir": os.path.join(BASE_DIR, "processed"),
    "atomic_red_events": os.path.join(BASE_DIR, "processed/atomic_red_events.json"),
    "caldera_events": os.path.join(BASE_DIR, "processed/caldera_events.json"),
    "cic_events": os.path.join(BASE_DIR, "processed/cic_events.json"),
    "cic_ml": os.path.join(BASE_DIR, "processed/cic_ml.json"),
    "darpa_events": os.path.join(BASE_DIR, ""),
    "splunk_detection_events": os.path.join(BASE_DIR,"processed/splunk_detections.jsonl"),
    "snort_rules": os.path.join(BASE_DIR,"processed/snort_rules.jsonl"),
    "llm_train_dataset": os.path.join(BASE_DIR, "processed/llm_train_file.jsonl"),
}

# =========================
# ENSURE OUTPUT DIRECTORIES EXIST
# =========================
os.makedirs(OUTPUT["processed_dir"], exist_ok=True)

# =========================
# MITRE / LABEL MAPPING
# =========================
ATTACK_MAPPING = {
    # ---------------- CIC ----------------
    "benign": (None, "benign"),

    "ddos": ("T1499", "impact"),
    "portscan": ("T1046", "discovery"),
    "bot": ("T1071", "command-and-control"),

    "web attack - brute force": ("T1110", "credential_access"),
    "web attack - xss": ("T1059", "execution"),
    "web attack - sql injection": ("T1190", "initial_access"),

    "infiltration": ("T1071", "command-and-control"),

    # ---------------- DARPA ----------------
    "pod": ("T1499", "impact"),
    "smurf": ("T1499", "impact"),
    "neptune": ("T1499", "impact"),
    "back": ("T1499", "impact"),
    "land": ("T1499", "impact"),

    "ipsweep": ("T1046", "discovery"),
    "portsweep": ("T1046", "discovery"),
    "nmap": ("T1046", "discovery"),

    "dictsimple": ("T1110", "credential_access"),
    "guesspasswd": ("T1110", "credential_access"),

    "warezclient": ("T1071", "command-and-control"),
    "warezmaster": ("T1071", "command-and-control"),
}

def normalize_label(label):
    if not label:
        return None

    return (
        label.lower()
        .replace("–", "-")
        .replace("_", "")
        .strip()
    )

def map_attack(label):
    norm = normalize_label(label)
    if norm in ATTACK_MAPPING:
        technique_id, category = ATTACK_MAPPING[norm]
        return technique_id, category

    return None, "unknown"
import json
import csv
import os
import pandas as pd

# --- Configuration ---
# Download the file from: https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json
MITRE_JSON_FILE = '/Users/gurpreetsingh/Downloads/enterprise-attack.json'
MITRE_TACTIC_TECHNIQUE_CSV = 'mitre_tactic_technique.csv'
MITRE_TACTIC_TECHNIQUE_GROUP_CSV = 'mitre_tactic_technique_group.csv'


def build_mitre_map(json_filepath, output_csv):
    """Extract tactic-technique mapping from MITRE ATT&CK STIX data."""
    
    # Check if file exists
    if not os.path.exists(json_filepath):
        print(f"ERROR: File not found at '{json_filepath}'")
        print("\nPlease download the MITRE ATT&CK STIX data:")
        print("1. Go to: https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json")
        print("2. Click 'Raw' or 'Download' to save the file")
        print(f"3. Save it as '{json_filepath}' in the same directory as this script")
        return

    print(f"Loading {json_filepath}...")
    with open(json_filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Step 1: Extract all tactics with their IDs and shortnames
    tactics = {}  # key = tactic_shortname, value = {id, name}
    
    for obj in data.get('objects', []):
        if obj.get('type') == 'x-mitre-tactic':
            # Get tactic ID (e.g., TA0001) from external_references
            tactic_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tactic_id = ref.get('external_id')
                    break
            
            # Get tactic shortname (e.g., 'defense-evasion')
            shortname = obj.get('x_mitre_shortname')
            
            if tactic_id and shortname:
                tactics[shortname] = {
                    'id': tactic_id,
                    'name': obj.get('name', 'Unknown')
                }
    
    print(f"Found {len(tactics)} tactics")

    # Step 2: Extract all techniques and map them to tactics via kill_chain_phases
    mappings = []
    techniques_found = 0
    
    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            # Skip if this is a sub-technique (can include or exclude as needed)
            is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
            
            # Get technique ID (e.g., T1055) from external_references
            technique_id = None
            technique_name = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    technique_name = obj.get('name', 'Unknown')
                    break
            
            if not technique_id:
                continue
            
            # Get tactics from kill_chain_phases
            kill_chain = obj.get('kill_chain_phases', [])
            
            for phase in kill_chain:
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactic_shortname = phase.get('phase_name')
                    
                    if tactic_shortname and tactic_shortname in tactics:
                        tactic = tactics[tactic_shortname]
                        mappings.append({
                            'tactic_id': tactic['id'],
                            'tactic_name': tactic['name'].lower(),
                            'tactic_shortname': tactic_shortname,
                            'technique_id': technique_id,
                            'technique_name': technique_name.lower(),
                            'is_subtechnique': is_subtechnique
                        })
                        techniques_found += 1
    
    print(f"Found {techniques_found} technique-tactic mappings")

    # Step 3: Write to CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['tactic_id', 'tactic_name', 'tactic_shortname', 'technique_id', 'technique_name', 'is_subtechnique']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for mapping in mappings:
            writer.writerow(mapping)
    
    print(f"\n✓ Successfully saved to: {output_csv}")
    print(f"  Total rows: {len(mappings)}")
    
    # Print sample
    print("\nSample output:")
    for i, m in enumerate(mappings[:10]):
        print(f"  {m['tactic_id']} | {m['technique_id']} | {m['technique_name'][:50]}...")


def groupByTechniques():
    df = pd.read_csv(MITRE_TACTIC_TECHNIQUE_CSV)
    grouped = df.groupby(['technique_id', 'technique_name']).agg(
        {
        'tactic_id': lambda x: '|'.join(x),
        'tactic_name': lambda x: '|'.join(x)
        }).reset_index()
    grouped.to_csv(MITRE_TACTIC_TECHNIQUE_GROUP_CSV, index=False)


if __name__ == "__main__":
    build_mitre_map(MITRE_JSON_FILE, MITRE_TACTIC_TECHNIQUE_CSV)
    groupByTechniques()
    
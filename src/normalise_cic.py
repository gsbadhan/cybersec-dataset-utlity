#!/usr/bin/env python3
"""
Complete CICIDS2017 Parser
Parses CICIDS2017 CSV files to structured JSON events with MITRE ATT&CK mapping
"""

import pandas as pd
import uuid
from datetime import datetime, timedelta
import json
import numpy as np
import sys
import os
import config

"""  awk -F',' '{count[$NF]++} END {for (label in count) print label, count[label]}' cic_machine_learning_cve_merged.csv
DDoS 128027
Infiltration 36
SSH-Patator 5897
Web Attack � XSS 652
Web Attack � Brute Force 1507
Heartbleed 11
DoS Slowhttptest 5499
 Label 1
DoS Hulk 231073
PortScan 158930
DoS GoldenEye 10293
FTP-Patator 7938
Bot 1966
Web Attack � Sql Injection 21
DoS slowloris 5796
BENIGN/UNKNOWN 2273097 """

"""🎯 Top Attack Types:
  DoS Hulk: 231,073 (41.6%)
  PortScan: 158,930 (28.6%)
  DDoS: 128,027 (23.0%)
  DoS GoldenEye: 10,293 (1.9%)
  FTP-Patator: 7,938 (1.4%)
  SSH-Patator: 5,897 (1.1%)
  DoS slowloris: 5,796 (1.0%)
  DoS Slowhttptest: 5,499 (1.0%)
  Bot: 1,966 (0.4%)
  Infiltration: 36 (0.0%)

🔬 MITRE Techniques Detected:
  T1498: 380,688 (13.5%)
  T1046: 158,930 (5.6%)
  T1110: 13,835 (0.5%)
  T1071: 2,002 (0.1%)
  T1190: 11 (0.0%)

🔌 Top 10 Destination Ports:
  Port 53: 957,971 (33.9%)
  Port 80: 616,754 (21.8%)
  Port 443: 505,710 (17.9%)
  Port 123: 23,880 (0.8%)
  Port 22: 16,941 (0.6%)
  Port 21: 13,522 (0.5%)
  Port 137: 7,917 (0.3%)
  Port 389: 6,406 (0.2%)
  Port 88: 5,580 (0.2%)
  Port 465: 3,817 (0.1%)"""


class RobustCICParser:
    """Robust parser for CICIDS2017 CSV that handles malformed data"""
    
    # MITRE ATT&CK mapping for CICIDS2017 attack types
    ATTACK_MAPPING = {
        'BENIGN': {'technique_id': None, 'technique_name': 'Benign', 'tactic': None, 'category': 'benign'},
        'FTP-Patator': {'technique_id': 'T1110', 'technique_name': 'Brute Force', 'tactic': 'TA0006', 'category': 'attack'},
        'SSH-Patator': {'technique_id': 'T1110', 'technique_name': 'Brute Force', 'tactic': 'TA0006', 'category': 'attack'},
        'DoS Hulk': {'technique_id': 'T1498', 'technique_name': 'Network Denial of Service', 'tactic': 'TA0040', 'category': 'attack'},
        'DoS GoldenEye': {'technique_id': 'T1498', 'technique_name': 'Network Denial of Service', 'tactic': 'TA0040', 'category': 'attack'},
        'DoS slowloris': {'technique_id': 'T1498', 'technique_name': 'Network Denial of Service', 'tactic': 'TA0040', 'category': 'attack'},
        'DoS Slowhttptest': {'technique_id': 'T1498', 'technique_name': 'Network Denial of Service', 'tactic': 'TA0040', 'category': 'attack'},
        'DDoS': {'technique_id': 'T1498', 'technique_name': 'Distributed Denial of Service', 'tactic': 'TA0040', 'category': 'attack'},
        'Web Attack – Brute Force': {'technique_id': 'T1110', 'technique_name': 'Brute Force', 'tactic': 'TA0006', 'category': 'attack'},
        'Web Attack – XSS': {'technique_id': 'T1189', 'technique_name': 'Drive-by Compromise', 'tactic': 'TA0001', 'category': 'attack'},
        'Web Attack – SQL Injection': {'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application', 'tactic': 'TA0001', 'category': 'attack'},
        'Infiltration': {'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol', 'tactic': 'TA0011', 'category': 'attack'},
        'Bot': {'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol', 'tactic': 'TA0011', 'category': 'attack'},
        'PortScan': {'technique_id': 'T1046', 'technique_name': 'Network Service Scanning', 'tactic': 'TA0007', 'category': 'attack'},
        'Heartbleed': {'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application', 'tactic': 'TA0001', 'category': 'attack'}
    }
    
    def __init__(self, base_timestamp=None):
        if base_timestamp is None:
            self.base_timestamp = datetime(2017, 7, 3, 9, 0, 0)
        else:
            self.base_timestamp = base_timestamp
        self.error_count = 0
        self.skip_count = 0
    
    def _safe_get_value(self, row, col_index, default=None):
        """Safely get a value from a row by index"""
        try:
            if col_index >= len(row):
                return default
            
            val = row.iloc[col_index]
            
            # Handle numpy/pandas types
            if isinstance(val, (pd.Series, np.ndarray)):
                if len(val) > 0:
                    val = val.iloc[0] if hasattr(val, 'iloc') else val[0]
                else:
                    return default
            
            # Check for NaN/None
            if pd.isna(val) or val is None:
                return default
            
            # Convert to string and check for empty
            str_val = str(val).strip()
            if str_val == '' or str_val == 'nan' or str_val == 'NaN':
                return default
            
            return val
        except Exception:
            return default
    
    def _safe_float(self, value):
        """Safely convert to float"""
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def _safe_int(self, value):
        """Safely convert to int"""
        if value is None:
            return None
        try:
            # Handle scientific notation and large numbers
            if isinstance(value, str) and 'e' in value.lower():
                return int(float(value))
            return int(float(value))
        except (ValueError, TypeError):
            return None
    
    def parse_csv(self, csv_path, sample_size=None, skip_invalid=True):
        """Parse CICIDS2017 CSV robustly"""
        
        if not os.path.exists(csv_path):
            print(f"Error: File not found: {csv_path}")
            return []
        
        print(f"Reading {csv_path}...")
        
        try:
            # Read CSV without type inference to avoid issues
            df = pd.read_csv(csv_path, dtype=str, low_memory=False)
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []
        
        # Clean column names
        df.columns = (
            df.columns
            .str.strip()
            .str.replace('.1', '', regex=False)
            .str.replace(' ', '_', regex=False)
            .str.replace('/', '_per_', regex=False)
            .str.replace('-', '_', regex=False)
            .str.lower()
        )
        
        print(f"✓ Loaded {len(df):,} rows with {len(df.columns)} columns")
        print(f"📋 Columns: {list(df.columns[:5])}... (total {len(df.columns)})")
        
        if sample_size:
            df = df.head(sample_size)
            print(f"🎯 Processing first {sample_size:,} rows")
        
        events = []
        label_col = df.columns[-1]  # Last column is Label
        
        print(f"Processing events...")
        
        for idx in range(len(df)):
            try:
                row = df.iloc[idx]
                
                # Get destination port (first column)
                dst_port_raw = self._safe_get_value(row, 0)
                dst_port = self._safe_int(dst_port_raw)
                
                # Get label (last column)
                label_raw = self._safe_get_value(row, len(df.columns) - 1, 'BENIGN')
                label = str(label_raw).strip() if label_raw else 'BENIGN'
                
                # Handle invalid labels
                if label not in self.ATTACK_MAPPING:
                    if skip_invalid:
                        self.skip_count += 1
                        continue
                    label = 'BENIGN'
                
                mitre_info = self.ATTACK_MAPPING.get(label, self.ATTACK_MAPPING['BENIGN'])
                
                # Generate timestamp (increment by 1ms per event)
                timestamp = self.base_timestamp + timedelta(milliseconds=idx)
                
                # Extract flow features
                flow_features = {}
                
                # Map of column indices to feature names (skip first and last)
                feature_indices = list(range(1, len(df.columns) - 1))
                
                for col_idx in feature_indices:
                    col_name = df.columns[col_idx]
                    raw_value = self._safe_get_value(row, col_idx)
                    
                    # Clean column name for JSON
                    clean_name = col_name.lower().replace(' ', '_').replace('/', '_per_').replace('-', '_').replace('(', '').replace(')', '')
                    
                    # Convert to float if possible
                    if raw_value is not None:
                        float_val = self._safe_float(raw_value)
                        flow_features[clean_name] = float_val if float_val is not None else str(raw_value)
                    else:
                        flow_features[clean_name] = None
                
                # Build event
                event = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": timestamp.isoformat(),
                    "src_ip": "0.0.0.0",  # Not available in CSV
                    "dst_ip": "0.0.0.0",  # Not available in CSV
                    "src_port": None,  # Not available in CSV
                    "dst_port": dst_port,
                    "protocol": None,  # Not available in CSV
                    "host": None,
                    "username": None,
                    "command": None,
                    "executor": None,
                    "flow_features": flow_features,
                    "technique_id": mitre_info['technique_id'],
                    "technique_name": mitre_info['technique_name'],
                    "tactic": mitre_info['tactic'],
                    "category": mitre_info['category'],
                    "activity_type": "network",
                    "status": "success" if mitre_info['category'] == 'benign' else "attack_detected",
                    "source": "cic",
                    "attack_type": label if mitre_info['category'] == 'attack' else None
                }
                
                events.append(event)
                
                # Progress indicator
                if (idx + 1) % 100000 == 0:
                    print(f"Processed {idx + 1:,} events...")
                    
            except Exception as e:
                self.error_count += 1
                if self.error_count <= 10:
                    print(f"Error processing row {idx}: {str(e)[:80]}")
                continue
        
        print(f"\nProcessing Summary:")
        print(f"Successfully parsed: {len(events):,} events")
        print(f"Errors: {self.error_count}")
        print(f"Skipped (invalid labels): {self.skip_count}")
        
        return events


def save_events_to_jsonl(events, output_path, max_events=None):
    """Save events to JSON lines format"""
    if max_events and len(events) > max_events:
        events = events[:max_events]
    
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    
    with open(output_path, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    file_size = os.path.getsize(output_path) / (1024 * 1024)  # Size in MB
    print(f"Saved {len(events)} events to {output_path} ({file_size:.2f} MB)")


def analyze_events(events):
    """Analyze parsed events"""
    total = len(events)
    
    if total == 0:
        print("No events to analyze")
        return
    
    attack_count = sum(1 for e in events if e['category'] == 'attack')
    benign_count = total - attack_count
    
    # Attack type distribution
    attack_types = {}
    for e in events:
        at = e.get('attack_type')
        if at:
            attack_types[at] = attack_types.get(at, 0) + 1
    
    # Port distribution
    ports = {}
    for e in events:
        port = e.get('dst_port')
        if port and port > 0:
            ports[port] = ports.get(port, 0) + 1
    
    # Technique distribution
    techniques = {}
    for e in events:
        tech = e.get('technique_id')
        if tech:
            techniques[tech] = techniques.get(tech, 0) + 1
    
    print("\n" + "=" * 70)
    print("📊 PARSING STATISTICS")
    print("=" * 70)
    print(f"📈 Total events: {total:,}")
    print(f"✅ Benign events: {benign_count:,} ({benign_count/total*100:.1f}%)")
    print(f"⚠️ Attack events: {attack_count:,} ({attack_count/total*100:.1f}%)")
    
    if attack_types:
        print("\n🎯 Top Attack Types:")
        for attack, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {attack}: {count:,} ({count/attack_count*100:.1f}%)")
    
    if techniques:
        print("\n🔬 MITRE Techniques Detected:")
        for tech, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {tech}: {count:,} ({count/total*100:.1f}%)")
    
    if ports:
        print("\n🔌 Top 10 Destination Ports:")
        for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  Port {port}: {count:,} ({count/total*100:.1f}%)")


def main():
    # Configuration - CHANGE THESE PATHS
    CSV_FILE = config.CIC.get("all_ml_cve_csv")  # CHANGE THIS to your actual file path
    OUTPUT_FILE = config.OUTPUT.get("cic_events")
    SAMPLE_SIZE = None  # Set to None for all rows, or number for testing (e.g., 100000)
    
    print("=" * 70)
    print("🚀 CICIDS2017 Robust Parser")
    print("=" * 70)
    print(f"📁 Input: {CSV_FILE}")
    print(f"📁 Output: {OUTPUT_FILE}")
    print(f"🎯 Sample size: {SAMPLE_SIZE if SAMPLE_SIZE else 'All rows'}")
    print("=" * 70)
    
    # Create parser
    parser = RobustCICParser(base_timestamp=datetime(2017, 7, 3, 9, 0, 0))
    
    # Parse CSV
    events = parser.parse_csv(CSV_FILE, sample_size=SAMPLE_SIZE)
    
    # Analyze events
    analyze_events(events)
    
    # Save to file
    save_events_to_jsonl(events, OUTPUT_FILE, max_events=None)
    
    print("\n" + "=" * 70)
    print("✅ PARSING COMPLETE!")
    print("=" * 70)


if __name__ == "__main__":
    from datetime import datetime
    main()
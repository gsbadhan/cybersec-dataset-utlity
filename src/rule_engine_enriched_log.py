import json
from asteval import Interpreter
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

"""
Enhanced Rule Engine with support for:
- count/len, contains, contains_any, matches, distinct_count, in_range, in (default)
- starts_with/ends_with
- Exact command matching
- Pattern matching
- Regex support
- AND/OR logical operations
- New event format support (nested structure with event, process, suspicious fields)
"""

class RuleEngine:
    def __init__(self, rules_path: str, rules_file_names: list[str]):
        """Initialize rule engine with rules from JSON file"""
        all_rules = []
        for name in rules_file_names:
            file_path = f"{rules_path}/{name}"
            with open(file_path, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    all_rules.append(rule)

        self.rules = all_rules    
        # Track matched rules for reporting
        self.match_history = []
    
    def _prepare_telemetry(self, telemetry: Dict) -> Dict:
        """
        Prepare telemetry data by flattening nested structures
        and extracting relevant fields for rule evaluation
        """
        prepared = {}
        
        # Flatten nested dictionaries
        def flatten_dict(data: Dict, prefix: str = '') -> Dict:
            result = {}
            for key, value in data.items():
                new_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    result.update(flatten_dict(value, new_key))
                else:
                    result[new_key] = value
            return result
        
        # ============================================================
        # NEW: Handle new event format with nested structure
        # ============================================================
        
        # Check if this is the new format (has 'event' and 'process' fields)
        if 'event' in telemetry and isinstance(telemetry['event'], dict):
            event_data = telemetry['event']
            
            # Extract from event object
            prepared['event_id'] = event_data.get('id', '')
            prepared['timestamp'] = event_data.get('timestamp', '')
            prepared['event_type'] = ','.join(event_data.get('type', []))
            prepared['activity'] = event_data.get('activity', [])
            prepared['category'] = event_data.get('category', [])
            prepared['source'] = event_data.get('source', '')
            
            # Extract from process object
            if 'process' in telemetry:
                process = telemetry['process']
                prepared['command'] = process.get('command_line', '')
                prepared['process_name'] = process.get('name', '')
                prepared['pid'] = process.get('pid', '')
                prepared['ppid'] = process.get('ppid', '')
                prepared['executor'] = process.get('executor', '')
                prepared['exit_code'] = process.get('exit_code', -1)
                prepared['status'] = process.get('status', '')
                prepared['process_user'] = process.get('user', '')
                prepared['process_host'] = process.get('host', '')
            
            # Extract from host object
            if 'host' in telemetry:
                host = telemetry['host']
                prepared['platform'] = host.get('platform', '')
                prepared['host_user'] = host.get('user', '')
                prepared['host_hostname'] = host.get('hostname', '')
                prepared['host_group'] = host.get('group', '')
                prepared['architecture'] = host.get('architecture', '')
            
            # Extract from suspicious object
            if 'suspicious' in telemetry:
                suspicious = telemetry['suspicious']
                prepared['suspicious_commands'] = suspicious.get('commands', [])
                prepared['suspicious_processes'] = suspicious.get('processes', [])
                prepared['suspicious'] = suspicious
            
            # Extract from mitre object
            if 'mitre' in telemetry and telemetry['mitre']:
                mitre = telemetry['mitre'][0] if isinstance(telemetry['mitre'], list) and telemetry['mitre'] else {}
                prepared['tactic_id'] = mitre.get('tactic_id', '')
                prepared['tactic_name'] = mitre.get('tactic_name', '')
                prepared['technique_id'] = mitre.get('technique_id', '')
                prepared['technique_name'] = mitre.get('technique_name', '')
                prepared['sub_technique_id'] = mitre.get('sub_technique_id', '')
                prepared['sub_technique_name'] = mitre.get('sub_technique_name', '')
            
            # Extract from source/destination
            if 'source' in telemetry:
                source = telemetry['source']
                prepared['source_ip'] = source.get('ip', '')
                prepared['source_asset_type'] = source.get('asset', {}).get('asset_type', '')
                prepared['source_hostname'] = source.get('asset', {}).get('hostname', '')
                prepared['source_os'] = source.get('asset', {}).get('os', '')
            
            if 'destination' in telemetry:
                destination = telemetry['destination']
                prepared['dest_ip'] = destination.get('ip', '')
                prepared['dest_asset_type'] = destination.get('asset', {}).get('asset_type', '')
                prepared['dest_hostname'] = destination.get('asset', {}).get('hostname', '')
                prepared['dest_os'] = destination.get('asset', {}).get('os', '')
            
            # Network info
            if 'network' in telemetry:
                network = telemetry['network']
                prepared['protocol'] = network.get('protocol', '')
                prepared['transport'] = network.get('transport', '')
                prepared['direction'] = network.get('direction', '')
                prepared['packets'] = network.get('packets', 0)
                prepared['bytes'] = network.get('bytes', 0)
        
        
        # Flatten any remaining nested structures
        prepared.update(flatten_dict(telemetry))
        
        return prepared
    
    def _create_evaluator(self, telemetry: Dict) -> Interpreter:
        """Create an asteval interpreter with aggregate functions"""
        aeval = Interpreter()
        
        # Add telemetry variables to symbol table
        prepared_telemetry = self._prepare_telemetry(telemetry)
        for key, value in prepared_telemetry.items():
            aeval.symtable[key] = value
        
        # Also add direct access to common fields
        aeval.symtable['command'] = prepared_telemetry.get('command', '')
        aeval.symtable['platform'] = prepared_telemetry.get('platform', '')
        aeval.symtable['executor'] = prepared_telemetry.get('executor', '')
        
        # Add suspicious fields for new format
        aeval.symtable['suspicious_commands'] = prepared_telemetry.get('suspicious_commands', [])
        aeval.symtable['suspicious_processes'] = prepared_telemetry.get('suspicious_processes', [])
        aeval.symtable['activity'] = prepared_telemetry.get('activity', [])
        
        # Register COUNT function
        def count_func(data):
            """Return the count/len of items in a list or dict"""
            if isinstance(data, (list, tuple, set)):
                return len(data)
            elif isinstance(data, dict):
                return len(data)
            elif data is None:
                return 0
            else:
                return 1
        aeval.symtable['count'] = count_func
        aeval.symtable['len'] = count_func

        # Register starts_with / ends_with
        def starts_with_func(string, prefix):
            if not isinstance(string, str):
                return False
            return string.startswith(prefix)
        
        def ends_with_func(string, suffix):
            if not isinstance(string, str):
                return False
            return string.endswith(suffix)
        
        aeval.symtable['starts_with'] = starts_with_func
        aeval.symtable['ends_with'] = ends_with_func

        # Register matches (regex)
        def matches_func(string, pattern):
            if not isinstance(string, str):
                return False
            try:
                return bool(re.search(pattern, string))
            except:
                return False
        aeval.symtable['matches'] = matches_func

        # Register regex_match for exact pattern matching
        def regex_match_func(string, pattern):
            if not isinstance(string, str):
                return False
            try:
                return bool(re.match(pattern, string))
            except:
                return False
        aeval.symtable['regex_match'] = regex_match_func

        # Register in_range
        def in_range_func(value, min_val, max_val):
            try:
                return min_val <= value <= max_val
            except:
                return False
        aeval.symtable['in_range'] = in_range_func

        # Register distinct_count
        def distinct_count_func(data):
            if isinstance(data, (list, tuple)):
                return len(set(data))
            elif isinstance(data, set):
                return len(data)
            elif isinstance(data, dict):
                return len(set(data.values()))
            return 1
        aeval.symtable['distinct_count'] = distinct_count_func

        # Register contains_any
        def contains_any_func(data, patterns):
            if not isinstance(data, (list, tuple)):
                return False
            for item in data:
                if item in patterns:
                    return True
            return False
        aeval.symtable['contains_any'] = contains_any_func

        # Register contains function (enhanced)
        def contains_func(data, item):
            """
            Check if item exists in data (string, list, tuple, set, dict)
            """
            if data is None:
                return False
            if isinstance(data, str):
                return str(item) in data
            elif isinstance(data, (list, tuple, set)):
                return item in data
            elif isinstance(data, dict):
                return item in data
            else:
                return data == item
        aeval.symtable['contains'] = contains_func

        # Register has_fields function
        def has_fields_func(data, fields):
            if not isinstance(data, dict):
                return False
            if isinstance(fields, str):
                return fields in data
            elif isinstance(fields, (list, tuple)):
                return all(field in data for field in fields)
            return False
        aeval.symtable['has_fields'] = has_fields_func

        # Register not_empty function
        def not_empty_func(data):
            if data is None:
                return False
            if isinstance(data, (list, tuple, set)):
                return len(data) > 0
            if isinstance(data, dict):
                return len(data) > 0
            if isinstance(data, str):
                return len(data.strip()) > 0
            return True
        aeval.symtable['not_empty'] = not_empty_func
        
        return aeval
    
    def evaluate_rule(self, rule: Dict, telemetry: Dict) -> bool:
        """
        Evaluate a single rule's condition string against telemetry data
        """
        if 'condition' not in rule:
            return True  # No condition means always match
        
        try:
            aeval = self._create_evaluator(telemetry)
            result = aeval(rule['condition'])
            
            # Check for explicit platform/executor requirements
            if 'platform' in rule and rule['platform']:
                prepared = self._prepare_telemetry(telemetry)
                # Check both new and old format platform fields
                platform = prepared.get('platform', '')
                if not platform:
                    platform = prepared.get('dest_os', '')
                if platform != rule['platform']:
                    return False
            
            if 'executor' in rule and rule['executor']:
                prepared = self._prepare_telemetry(telemetry)
                executor = prepared.get('executor', '')
                if not executor:
                    executor = prepared.get('process.executor', '')
                if executor != rule['executor']:
                    return False
            
            return result if isinstance(result, bool) else False
            
        except Exception as e:
            print(f"Error evaluating rule {rule.get('rule_id', 'unknown')}: {e}")
            return False
    
    def check_all_rules(self, telemetry: Union[Dict, List]) -> List[Dict]:
        """
        Check all rules against telemetry data
        
        Args:
            telemetry: Single event dict or list of events
            
        Returns:
            List of matched rules with event context
        """
        # Convert single event to list for uniform processing
        events = [telemetry] if isinstance(telemetry, dict) else telemetry
        
        all_alerts = []
        
        for event in events:
            event_alerts = []
            
            for rule in self.rules:
                # Check if rule applies to this event
                if self.evaluate_rule(rule, event):
                    # Extract command from either format
                    command = ''
                    if 'process' in event and isinstance(event['process'], dict):
                        command = event['process'].get('command_line', '')
                    else:
                        command = event.get('plaintext_command', event.get('command', ''))
                    
                    alert = {
                        'rule_id': rule.get('rule_id', 'unknown'),
                        'rule_type': rule.get('rule_type', 'unknown'),
                        'severity': rule.get('severity', 0.0),
                        'technique_id': rule.get('technique_id', ''),
                        'description': rule.get('description', ''),
                        'platform': rule.get('platform', ''),
                        'matched_condition': rule.get('condition', ''),
                        'event_command': command
                    }
                    
                    # Add extra context from new format
                    if 'host' in event:
                        alert['host'] = event['host'].get('hostname', '')
                        alert['username'] = event['host'].get('user', '')
                    
                    
                    # Add MITRE info from new format
                    if 'mitre' in event and event['mitre']:
                        mitre = event['mitre'][0] if isinstance(event['mitre'], list) and event['mitre'] else {}
                        alert['mitre_technique_id'] = mitre.get('technique_id', '')
                        alert['mitre_sub_technique_id'] = mitre.get('sub_technique_id', '')
                    
                    # Add suspicious info from new format
                    if 'suspicious' in event:
                        suspicious = event['suspicious']
                        alert['suspicious_commands'] = suspicious.get('commands', [])
                        alert['suspicious_processes'] = suspicious.get('processes', [])
                    
                    event_alerts.append(alert)
            
            if event_alerts:
                # Extract timestamp from either format
                timestamp = ''
                if 'event' in event and isinstance(event['event'], dict):
                    timestamp = event['event'].get('timestamp', '')
                else:
                    timestamp = event.get('delegated_timestamp', '')
                
                all_alerts.append({
                    'event': {
                        'timestamp': timestamp,
                        'command': command,
                        'platform': event.get('platform', event.get('dest_os', '')),
                        'status': event.get('status', event.get('exit_code', -1))
                    },
                    'matches': event_alerts,
                    'total_matches': len(event_alerts),
                    'max_severity': max([a['severity'] for a in event_alerts]) if event_alerts else 0
                })
        
        # Update match history
        self.match_history.extend(all_alerts)
        
        return all_alerts
    
    def get_statistics(self) -> Dict:
        """Get statistics about rule matches"""
        total_matches = 0
        rules_matched = set()
        score = 0

        for entry in self.match_history:
            total_matches += entry['total_matches']
            for match in entry['matches']:
                rules_matched.add(match['rule_id'])
                score += match['severity']
        
        return {
            'total_events_processed': len(self.match_history),
            'total_rule_matches': total_matches,
            'unique_rules_matched': len(rules_matched),
            'matched_rule_ids': list(rules_matched),
            'avg_score': (score / len(rules_matched)) if rules_matched else 0,
            'critical_count>=0.8': len(self.get_matches_by_severity(0.8))
        }
    
    def get_matches_by_severity(self, min_severity: float = 0.7) -> List[Dict]:
        """Get all matches with severity above threshold"""
        high_severity_matches = []
        
        for entry in self.match_history:
            for match in entry['matches']:
                if match['severity'] >= min_severity:
                    high_severity_matches.append(match)
        
        return high_severity_matches


# Example usage
if __name__ == "__main__":
    rule_files = ["cyber_rules_001.json", "cyber_rules_002.json"]
    engine = RuleEngine(
        rules_path="/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/rules/",
        rules_file_names=rule_files
    )
    
    # Load enriched security logs
    with open('/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/data/caldera_sample_enriched_events.json', 'r') as f:
        events = json.load(f)
    
    # Process all events
    results = engine.check_all_rules(events)
    
    # Print summary
    print(f"Processed {len(events)} events")
    print(f"Found {len(results)} events with rule matches")
    
    # Print detailed results
    for result in results:
        print(f"\nEvent: {result['event']['command'][:100]}...")
        print(f"Total Matches: {result['total_matches']}")
        print(f"Max Severity: {result['max_severity']}")
        for match in result['matches']:
            print(f"  - {match['rule_id']}: {match['description']} Severity: {match['severity']}")
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"\nStatistics:")
    print(json.dumps(stats, indent=2))
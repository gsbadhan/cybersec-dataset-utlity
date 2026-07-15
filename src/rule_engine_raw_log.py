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
"""

class RuleEngine:
    def __init__(self, rules_path: str, rules_file_names: list[str]):
        """Initialize rule engine with rules from JSON file"""
        all_rules= []
        for name in rules_file_names:
            file= rules_path + "/" + name
            with open(file, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    all_rules.append(rule)

        self.rules= all_rules    
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
        
        # Extract common fields from Caldera events
        if 'plaintext_command' in telemetry:
            prepared['command'] = telemetry.get('plaintext_command', telemetry.get('command', ''))
        else:
            prepared['command'] = telemetry.get('command', '')
        
        prepared['executor'] = telemetry.get('executor', '')
        prepared['platform'] = telemetry.get('platform', '')
        prepared['status'] = telemetry.get('status', -1)
        
        # Extract agent metadata
        if 'agent_metadata' in telemetry:
            agent = telemetry['agent_metadata']
            prepared['agent_username'] = agent.get('username', '')
            prepared['agent_host'] = agent.get('host', '')
            prepared['agent_privilege'] = agent.get('privilege', '')
            prepared['agent_architecture'] = agent.get('architecture', '')
        
        # Extract ability metadata
        if 'ability_metadata' in telemetry:
            prepared['ability_id'] = telemetry['ability_metadata'].get('ability_id', '')
            prepared['ability_name'] = telemetry['ability_metadata'].get('ability_name', '')
            prepared['ability_description'] = telemetry['ability_metadata'].get('ability_description', '')
        
        # Extract attack metadata
        if 'attack_metadata' in telemetry:
            prepared['tactic'] = telemetry['attack_metadata'].get('tactic', '')
            prepared['technique_id'] = telemetry['attack_metadata'].get('technique_id', '')
            prepared['technique_name'] = telemetry['attack_metadata'].get('technique_name', '')
        
        # Extract operation metadata
        if 'operation_metadata' in telemetry:
            prepared['operation_name'] = telemetry['operation_metadata'].get('operation_name', '')
        
        # Add timestamps
        prepared['delegated_timestamp'] = telemetry.get('delegated_timestamp', '')
        prepared['finished_timestamp'] = telemetry.get('finished_timestamp', '')
        
        # Add PID
        prepared['pid'] = telemetry.get('pid', '')
        
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
                if prepared.get('platform', '') != rule['platform']:
                    return False
            
            if 'executor' in rule and rule['executor']:
                prepared = self._prepare_telemetry(telemetry)
                if prepared.get('executor', '') != rule['executor']:
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
                    alert = {
                        'rule_id': rule.get('rule_id', 'unknown'),
                        'rule_type': rule.get('rule_type', 'unknown'),
                        'severity': rule.get('severity', 0.0),
                        'technique_id': rule.get('technique_id', ''),
                        'description': rule.get('description', ''),
                        'platform': rule.get('platform', ''),
                        'matched_condition': rule.get('condition', ''),
                        'event_command': event.get('plaintext_command', event.get('command', ''))
                    }
                    
                    # Add extra context if available
                    if 'agent_metadata' in event:
                        alert['host'] = event['agent_metadata'].get('host', '')
                        alert['username'] = event['agent_metadata'].get('username', '')
                    
                    if 'attack_metadata' in event:
                        alert['event_technique'] = event['attack_metadata'].get('technique_id', '')
                    
                    event_alerts.append(alert)
            
            if event_alerts:
                all_alerts.append({
                    'event': {
                        'timestamp': event.get('delegated_timestamp', ''),
                        'command': event.get('plaintext_command', event.get('command', '')),
                        'platform': event.get('platform', ''),
                        'status': event.get('status', -1)
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
        score= 0

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
            'avg_score': (score/len(rules_matched)),
            'critical_count>=0.8': len(engine.get_matches_by_severity(0.8))
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
    rule_files= ["cyber_rules_001.json", "cyber_rules_002.json"]
    engine = RuleEngine(rules_path="/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/rules/", rules_file_names=rule_files)
        
    # Load security logs from Caldera events
    with open('/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/data/caldera_sample_raw_events.json', 'r') as f:
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
    
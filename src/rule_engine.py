import json
from asteval import Interpreter
import re
"""
functions supported:

- count/len, contains, contains_any, mathces, distinct_count, in_range, in (default),  
- starts_with/ends_with

"""

class RuleEngine:
    def __init__(self, rules_file):
        with open(rules_file, 'r') as f:
            self.rules = json.load(f)
    
    def _create_evaluator(self, telemetry):
        """Create an asteval interpreter with aggregate functions"""
        aeval = Interpreter()
        
        # Add telemetry variables to symbol table
        for key, value in telemetry.items():
            aeval.symtable[key] = value
        
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
                return 1  # Single value counts as 1
        aeval.symtable['count'] = count_func
        # Also add len as alias for count
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

        # Register not function (negation helper)
        def not_func(value):
            return not value
        aeval.symtable['not'] = not_func

        # Register contains_any
        def contains_any_func(data, patterns):
            if not isinstance(data, (list, tuple)):
                return False
            for item in data:
                if item in patterns:
                    return True
            return False
        aeval.symtable['contains_any'] = contains_any_func

        # Register contains function
        def contains_func(data, item):
            """
            Check if item exists in data (string, list, tuple, set, dict)
            
            Examples:
            contains('hello world', 'world') -> True
            contains(['a', 'b', 'c'], 'b') -> True
            contains({'key1': 'value1', 'key2': 'value2'}, 'key1') -> True (checks keys)
            """
            if data is None:
                return False
            # For strings - substring check
            if isinstance(data, str):
                return str(item) in data
            # For lists, tuples, sets - item existence
            elif isinstance(data, (list, tuple, set)):
                return item in data
            # For dictionaries - check if key exists
            elif isinstance(data, dict):
                return item in data
            # For other types - equality check
            else:
                return data == item
        
        aeval.symtable['contains'] = contains_func
        
        return aeval
    
    def evaluate_rule(self, rule, telemetry):
        """Evaluate a single rule's condition string"""
        if 'condition' not in rule:
            return True  # No condition means always match
        
        try:
            aeval = Interpreter()
            for key, value in telemetry.items():
                aeval.symtable[key] = value

            aeval = self._create_evaluator(telemetry)
            result = aeval(rule['condition'])    
            return result
        except Exception as e:
            print(f"Error evaluating {rule['rule_id']}: {e}")
            return False
    
    
    def check_all_rules(self, telemetry):
        """Check all rules against telemetry data"""
        alerts = []
        for rule in self.rules:
            if self.evaluate_rule(rule, telemetry):
                alerts.append({
                    'rule_id': rule['rule_id'],
                    'rule_type': rule['rule_type'],
                    'severity': rule.get('severity', 0),
                    'technique_id': rule.get('technique_id')
                })
        return alerts

# Usage
engine = RuleEngine("src/cyber_rules.json")

# Check network traffic
network_traffic = {
    'flow_bytes_s': 1500000,
    'bwd_packet_length_max': 5000
}

process_data = {
    'command': 'find / -name "*.wav" -type f -not -path "*/.*" -size -500k 2>/dev/null | head -5',
    'executor': 'sh',
    'platform': 'linux'
}

audit_data = {
    'event': 'ioctl(2)',
    'audit_id': -2,
    'path': '/dev/',
    'platform': 'solaris'
}

failed_logins_count = {
    'failed_logins': ['user1', 'user2', 'user1', 'user1', 'user4'],
    'user': 'user1'
}

suspicious_processes_count = {
    'suspicious_processes': ['malware.exe', 'unknown.sh', 'suspicious.bin']
}
process_exist={
    'command': ['wget', 'curl', 'find']
}


# [{'rule_id': 'rl-1290', 'severity': 0.90, 'technique_id': 'T1498'}]
alerts = engine.check_all_rules(network_traffic)
print(alerts)

alerts = engine.check_all_rules(process_data)
print(alerts)

alerts = engine.check_all_rules(audit_data)
print(alerts)

alerts = engine.check_all_rules(failed_logins_count)
print(alerts)

alerts = engine.check_all_rules(suspicious_processes_count)
print(alerts)

alerts = engine.check_all_rules(process_exist)
print(alerts)
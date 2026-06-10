"""
Snort Rule Parser - Simple Single Line Version
Parses Snort rules and extracts fields into structured JSON
"""

import re
import json
from typing import Dict, List
from pathlib import Path
import config


class SnortRuleParser:
    """Parse Snort rules and extract structured fields"""
    
    def parse_rule(self, rule_line: str) -> Dict:
        """Parse a single Snort rule line"""
        
        result = {
            "sid": "",
            "protocol": "",
            "src_ip": "",
            "src_port": "",
            "dst_ip": "",
            "dst_port": "",
            "direction": "outbound",
            "msg": "",
            "flow": "",
            "content": [],
            "metadata": "",
            "class_type": "",
            "icode": "",
            "itype": "",
            "snort_type": "alert",
            "source": "snort",
            "reference": {
                "cve": [],
                "mitre": [],
                "url": []
            }
        }
        
        print(rule_line)
        address_msg=rule_line.split("( msg")
        address = address_msg[0]
        msg = address_msg[1]
        # address section
        address_parts = address.split(" ")
        result["snort_type"] = "" if len(address_parts) <= 0 else address_parts[0]
        result["protocol"] = "" if len(address_parts) <= 1 else address_parts[1] 
        result["src_ip"] = "" if len(address_parts) <= 2 else address_parts[2]
        result["src_port"] = "" if len(address_parts) <= 3 else address_parts[3]
        if len(address_parts) >= 4:
            result["direction"] = "outbound" if address_parts[4] == "->" else ("inbound" if address_parts[4] == "<-" else "")
        result["dst_ip"] = "" if len(address_parts) <= 5 else address_parts[5]
        result["dst_port"] = "" if len(address_parts) <= 6 else address_parts[6]
        # msg section
        msg_parts = msg.split(";")
        for part in msg_parts:
            print(part)
            section = part.split(":")
            key = section[0].lower().strip()
            match key:
                case "msg":
                    result["msg"]=self.clean(section[1])
                case "sid":     
                    result["sid"]=self.clean(section[1])
                case "flow":
                    result["flow"]=self.clean(section[1])
                case "content":
                    result["content"]=self.clean(section[1])
                case "metadata":
                    result["metadata"]=self.clean(section[1])
                case "classtype":
                    result["class_type"]=self.clean(section[1])
                case "reference":
                    self.parse_reference(section[1].strip(), result["reference"])
                case "icode":
                    result["icode"]=self.clean(section[1])
                case "itype":
                    result["itype"]=self.clean(section[1])
                case _:
                    None

        return result
    
    def clean(self, value):
        return value.replace('"','').strip()
    
    def parse_reference(self, ref_str: str, ref_dict: Dict):
        """Parse reference field and extract CVE, MITRE, URLs"""
        
        parts = ref_str.split(',')
        
        i = 0
        while i < len(parts):
            part = parts[i].strip()
            
            # CVE: cve,2000-0138
            if part.lower() == 'cve' and i + 1 < len(parts):
                cve_id = parts[i + 1].strip()
                if not cve_id.upper().startswith('CVE-'):
                    ref_dict["cve"].append(f"CVE-{cve_id}")
                else:
                    ref_dict["cve"].append(cve_id.upper())
                i += 2
                continue
            
            # MITRE: attack.mitre.org/techniques/T1078
            if 'attack.mitre.org' in part:
                tech_match = re.search(r'T\d{4}(?:\.\d{3})?', part, re.IGNORECASE)
                if tech_match:
                    ref_dict["mitre"].append(tech_match.group(0).upper())
                i += 1
                continue
            
            # URL
            if part.startswith('http') or 'www.' in part or '.com' in part or '.org' in part:
                ref_dict["url"].append(part)
                i += 1
                continue
            
            i += 1

        return ref_dict    
    
    def parse_file(self, filepath: str) -> List[Dict]:
        rules = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                rule=self.parse_rule(line)       
                rules.append(rule)
        return rules


def parse_all():
    """Parse Snort rules and save as JSON lines"""
    
    file_path = config.SNORT.get("rules")
    output_file_path = config.OUTPUT.get("snort_rules")
    parser = SnortRuleParser()
    events = parser.parse_file(filepath=file_path)
    
    print(f"✅ Parsed {len(events)} rules")
    
    # Write output
    with open(output_file_path, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"💾 Saved to: {output_file_path}")
    
    # Print sample
    if events:
        print("\n📋 Sample parsed rule:")
        print(json.dumps(events[0], indent=2))


if __name__ == "__main__":
    parse_all()
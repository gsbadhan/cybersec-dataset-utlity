"""
parsed DARPA pascal.log which come from pascal.bsm
"""

import json
from typing import Dict, List, Any, Optional

class BSMParser:
    """Parser for Solaris BSM audit records from praudit output"""
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse praudit output file into structured records"""
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Split into lines
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        # Find record boundaries using trailer tokens
        records = self._split_by_trailers(lines)
        
        parsed_records = []
        for record_lines in records:
            parsed = self._parse_record(record_lines)
            parsed_records.append(parsed)
        
        return parsed_records
    
    def _split_by_trailers(self, lines: List[str]) -> List[List[str]]:
        """
        Split records by detecting 'trailer' tokens.
        Each complete record ends with a 'trailer' token.
        The next token after trailer starts a new record.
        """
        records = []
        current_record = []
        
        for i, line in enumerate(lines):
            current_record.append(line)
            
            # If this line is a trailer token, end the current record
            if line.startswith('trailer,'):
                records.append(current_record)
                current_record = []
        
        # Handle any remaining lines (shouldn't happen with valid input)
        if current_record:
            records.append(current_record)
        
        return records
    
    def _parse_record(self, lines: List[str]) -> Dict:
        """Parse individual record lines into structured dict"""
        record = {
            "tokens": {},
            "raw_tokens": lines
        }
        
        # Parse each line into a token
        for line in lines:
            token = self._parse_token_line(line)
            if token:
                token_type = token.pop("type")
                if token_type not in record["tokens"]:
                    record["tokens"][token_type] = []
                record["tokens"][token_type].append(token)
        
        # Extract common fields into top-level
        self._extract_common_fields(record)
        
        return record
    
    def _parse_token_line(self, line: str) -> Optional[Dict]:
        """Parse a single token line into structured fields"""
        comma_pos = line.find(',')
        if comma_pos == -1:
            return None
        
        token_type = line[:comma_pos].strip()
        fields_str = line[comma_pos + 1:].strip()
        
        # Parse fields
        fields = self._split_fields(fields_str)
        
        # Route to appropriate parser
        parsers = {
            "file": self._parse_file,
            "header": self._parse_header,
            "subject": self._parse_subject,
            "process": self._parse_process,
            "return": self._parse_return,
            "argument": self._parse_argument,
            "arg": self._parse_argument,
            "path": self._parse_path,
            "attribute": self._parse_attribute,
            "attr": self._parse_attribute,
            "trailer": self._parse_trailer,
            "exit": self._parse_exit,
            "exec_args": self._parse_exec_args,
            "exec_env": self._parse_exec_env,
            "groups": self._parse_groups,
            "ipc": self._parse_ipc,
            "ipc_perm": self._parse_ipc_perm,
            "socket": self._parse_socket,
            "text": self._parse_text,
            "seq": self._parse_seq,
        }
        
        parser = parsers.get(token_type, self._parse_generic)
        return parser(token_type, fields)
    
    def _split_fields(self, fields_str: str) -> List[str]:
        """Split fields respecting quoted strings"""
        fields = []
        current = ""
        in_quotes = False
        quote_char = None
        
        i = 0
        while i < len(fields_str):
            char = fields_str[i]
            
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
                current += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current += char
            elif char == ',' and not in_quotes:
                fields.append(current.strip())
                current = ""
            else:
                current += char
            i += 1
        
        fields.append(current.strip())
        
        # Clean up fields
        fields = [self._clean_field(f) for f in fields]
        
        return fields
    
    def _clean_field(self, field: str) -> Optional[str]:
        """Clean field by stripping quotes and handling empty values"""
        if not field:
            return None
        
        # Remove surrounding quotes
        if len(field) >= 2 and (field[0] == '"' or field[0] == "'") and field[0] == field[-1]:
            field = field[1:-1]
        
        return field if field else None
    
    def _parse_int(self, value: Any) -> Any:
        """Safely parse integer"""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return value
    
    def _parse_file(self, token_type: str, fields: List[str]) -> Dict:
        """file token: timestamp, milliseconds, [additional]"""
        result = {"type": token_type}
        if len(fields) >= 1 and fields[0]:
            result["timestamp"] = fields[0]
        if len(fields) >= 2 and fields[1]:
            result["milliseconds"] = fields[1]
        if len(fields) >= 3 and fields[2]:
            result["additional_info"] = fields[2]
        return result
    
    def _parse_header(self, token_type: str, fields: List[str]) -> Dict:
        """header token: size, version, event_type, modifier, timestamp, milliseconds"""
        result = {"type": token_type}
        if len(fields) >= 1:
            result["size"] = self._parse_int(fields[0])
        if len(fields) >= 2:
            result["version"] = self._parse_int(fields[1])
        if len(fields) >= 3:
            result["event_type"] = fields[2]
        if len(fields) >= 4:
            result["event_modifier"] = fields[3] if fields[3] else None
        if len(fields) >= 5:
            result["timestamp"] = fields[4]
        if len(fields) >= 6:
            result["milliseconds"] = fields[5]
        return result
    
    def _parse_subject(self, token_type: str, fields: List[str]) -> Dict:
        """subject token: audit_id, real_uid, real_gid, eff_uid, eff_gid, pid, sid, terminal, host"""
        result = {"type": token_type}
        if len(fields) >= 1:
            result["audit_id"] = self._parse_int(fields[0])
        if len(fields) >= 2:
            result["real_uid"] = fields[1]
        if len(fields) >= 3:
            result["real_gid"] = fields[2]
        if len(fields) >= 4:
            result["effective_uid"] = fields[3]
        if len(fields) >= 5:
            result["effective_gid"] = fields[4]
        if len(fields) >= 6:
            result["process_id"] = self._parse_int(fields[5])
        if len(fields) >= 7:
            result["session_id"] = self._parse_int(fields[6])
        if len(fields) >= 8:
            result["terminal"] = fields[7]
        if len(fields) >= 9:
            result["host_address"] = fields[8]
        return result
    
    def _parse_process(self, token_type: str, fields: List[str]) -> Dict:
        return self._parse_subject(token_type, fields)
    
    def _parse_return(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["status"] = fields[0]
        if len(fields) >= 2:
            result["return_value"] = self._parse_int(fields[1])
        return result
    
    def _parse_argument(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["arg_num"] = self._parse_int(fields[0])
        if len(fields) >= 2:
            result["value"] = fields[1]
        if len(fields) >= 3:
            result["description"] = fields[2]
        return result
    
    def _parse_path(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["path"] = fields[0]
        return result
    
    def _parse_attribute(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["mode"] = fields[0]
        if len(fields) >= 2:
            result["owner_uid"] = fields[1]
        if len(fields) >= 3:
            result["owner_gid"] = fields[2]
        if len(fields) >= 4:
            result["fsid"] = self._parse_int(fields[3])
        if len(fields) >= 5:
            result["node_id"] = self._parse_int(fields[4])
        if len(fields) >= 6:
            result["device"] = fields[5]
        return result
    
    def _parse_trailer(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["size"] = self._parse_int(fields[0])
        return result
    
    def _parse_exit(self, token_type: str, fields: List[str]) -> Dict:
        return self._parse_return(token_type, fields)
    
    def _parse_exec_args(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        result["arguments"] = fields
        return result
    
    def _parse_exec_env(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        result["environment"] = fields
        return result
    
    def _parse_groups(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        result["groups"] = fields
        return result
    
    def _parse_ipc(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["object_type"] = fields[0]
        if len(fields) >= 2:
            result["handle"] = self._parse_int(fields[1])
        return result
    
    def _parse_ipc_perm(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["owner_uid"] = fields[0]
        if len(fields) >= 2:
            result["owner_gid"] = fields[1]
        if len(fields) >= 3:
            result["creator_uid"] = fields[2]
        if len(fields) >= 4:
            result["creator_gid"] = fields[3]
        if len(fields) >= 5:
            result["mode"] = fields[4]
        if len(fields) >= 6:
            result["seq"] = self._parse_int(fields[5])
        if len(fields) >= 7:
            result["key"] = fields[6]
        return result
    
    def _parse_socket(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["socket_type"] = fields[0]
        if len(fields) >= 2:
            result["remote_port"] = self._parse_int(fields[1])
        if len(fields) >= 3:
            result["remote_address"] = fields[2]
        return result
    
    def _parse_text(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["text"] = fields[0]
        return result
    
    def _parse_seq(self, token_type: str, fields: List[str]) -> Dict:
        result = {"type": token_type}
        if len(fields) >= 1:
            result["sequence_number"] = self._parse_int(fields[0])
        return result
    
    def _parse_generic(self, token_type: str, fields: List[str]) -> Dict:
        return {"type": token_type, "fields": fields}
    
    def _extract_common_fields(self, record: Dict) -> None:
        """Extract commonly used fields to top level"""
        tokens = record.get("tokens", {})
        
        # Header (primary event info)
        if "header" in tokens and tokens["header"]:
            header = tokens["header"][0]
            record["event_type"] = header.get("event_type")
            record["timestamp"] = header.get("timestamp")
            record["record_size"] = header.get("size")
            record["event_version"] = header.get("version")
        
        # Subject (who)
        if "subject" in tokens and tokens["subject"]:
            subject = tokens["subject"][0]
            record["subject_audit_id"] = subject.get("audit_id")
            record["subject_uid"] = subject.get("effective_uid")
            record["subject_pid"] = subject.get("process_id")
            record["session_id"] = subject.get("session_id")
        
        # Return (result)
        if "return" in tokens and tokens["return"]:
            ret = tokens["return"][0]
            record["return_status"] = ret.get("status")
            record["return_value"] = ret.get("return_value")
        
        # Path (file operations)
        if "path" in tokens and tokens["path"]:
            record["file_path"] = tokens["path"][0].get("path")
        
        # Arguments
        if "argument" in tokens:
            record["arguments"] = tokens["argument"]

def save_json(events, path):
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

def main():
    parser = BSMParser()
    records = parser.parse_file("/Users/gurpreetsingh/Downloads/cybersec-dataset/darpa/1998/week1/monday/pascal_sample.log")
    print(json.dumps(records, indent=2))
    save_json(events=records, path="/Users/gurpreetsingh/Downloads/cybersec-dataset/darpa/1998/week1/monday/parsed_pascal_sample.log")

if __name__ == "__main__":
    main()
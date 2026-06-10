
"""
Simple TCPDUMP Parser for DARPA 1999
Parses TCP packets with flags, sequence numbers, and application data
"""

import re
import uuid
import json
from typing import Dict, List, Optional
import os

class SimpleTCPDumpParser:
    """Parse DARPA 1999 tcpdump logs into structured JSON"""
    
    def __init__(self, source: str = "darpa1999", week: str = "week1", day: str = "monday"):
        self.source = source
        self.week = week
        self.day = day
        self.event_counter = 0
    
    def parse_file(self, filepath: str, limit: int = None) -> List[Dict]:
        """Parse tcpdump file and return list of events"""
        events = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip hex dump lines
            if line.startswith('0x'):
                continue
            
            event = self._parse_line(line)
            if event:
                events.append(event)
                self.event_counter += 1
                
                if limit and len(events) >= limit:
                    break
        
        return events
    
    def _parse_line(self, line: str) -> Optional[Dict]:
        """Parse a single tcpdump line"""
        
        # Extract timestamp (format: 18:30:05.928772)
        time_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)', line)
        if not time_match:
            return None
        
        timestamp = time_match.group(1)
        
        # Default values
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = None
        dst_port = None
        protocol = "UNKNOWN"
        packet_info = line[:100]
        tcp_flags = None
        
        # Parse IP packets
        # Pattern matches: IP src_ip.src_port > dst_ip.dst_port:
        ip_pattern = r'IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):'
        ip_match = re.search(ip_pattern, line)
        
        if ip_match:
            src_ip = ip_match.group(1)
            src_port = int(ip_match.group(2))
            dst_ip = ip_match.group(3)
            dst_port = int(ip_match.group(4))
            
            # Determine protocol based on destination port or content
            if dst_port == 25 or src_port == 25 or 'SMTP' in line:
                protocol = 'SMTP'
            elif dst_port == 53 or src_port == 53 or 'DNS' in line:
                protocol = 'DNS'
            elif 'NTP' in line or dst_port == 123 or src_port == 123:
                protocol = 'NTP'
            elif 'RIP' in line or dst_port == 520 or src_port == 520:
                protocol = 'RIP'
            elif dst_port == 80 or src_port == 80:
                protocol = 'HTTP'
            elif dst_port == 443 or src_port == 443:
                protocol = 'HTTPS'
            elif dst_port == 22 or src_port == 22:
                protocol = 'SSH'
            elif dst_port == 21 or src_port == 21:
                protocol = 'FTP'
            elif dst_port == 110 or src_port == 110:
                protocol = 'POP3'
            elif dst_port == 143 or src_port == 143:
                protocol = 'IMAP'
            else:
                protocol = 'TCP'
            
            # Extract TCP flags
            flags_match = re.search(r'Flags \[([^\]]+)\]', line)
            if flags_match:
                flags = flags_match.group(1)
                tcp_flags = flags
                
                # Create readable flag description
                flag_desc = []
                if 'S' in flags and '.' in flags:
                    flag_desc.append("SYN-ACK")
                elif 'S' in flags:
                    flag_desc.append("SYN")
                elif 'F' in flags:
                    flag_desc.append("FIN")
                elif 'R' in flags:
                    flag_desc.append("RST")
                elif '.' in flags or 'A' in flags:
                    flag_desc.append("ACK")
                if 'P' in flags:
                    flag_desc.append("PSH")
                if 'U' in flags:
                    flag_desc.append("URG")
                
                packet_info = f"TCP {'-'.join(flag_desc) if flag_desc else flags}"
                
                # Extract sequence number
                seq_match = re.search(r'seq\s+(\d+)', line)
                if seq_match:
                    packet_info += f" seq={seq_match.group(1)}"
                
                # Extract ack number
                ack_match = re.search(r'ack\s+(\d+)', line)
                if ack_match:
                    packet_info += f" ack={ack_match.group(1)}"
                
                # Extract length
                len_match = re.search(r'length\s+(\d+)', line)
                if len_match:
                    length = int(len_match.group(1))
                    if length > 0:
                        packet_info += f" length={length}"
            
            # Extract application data (SMTP, DNS, etc.)
            if 'SMTP' in line or 'smtp' in line.lower():
                smtp_match = re.search(r':\s*(.+)$', line)
                if smtp_match:
                    packet_info = smtp_match.group(1).strip()[:80]
                    protocol = 'SMTP'
            elif 'PTR?' in line or 'A?' in line:
                dns_match = re.search(r':\s*(.+)$', line)
                if dns_match:
                    packet_info = dns_match.group(1).strip()[:80]
                    protocol = 'DNS'
        
        # Parse ARP packets
        elif 'ARP' in line:
            protocol = 'ARP'
            who_has = re.search(r'who-has\s+(\d+\.\d+\.\d+\.\d+)', line)
            tell = re.search(r'tell\s+(\d+\.\d+\.\d+\.\d+)', line)
            
            if who_has:
                dst_ip = who_has.group(1)
            if tell:
                src_ip = tell.group(1)
            
            packet_info = line[line.find('ARP'):].strip()[:80]
        
        # Parse other protocols
        elif 'CDP' in line:
            protocol = 'CDP'
            packet_info = line[line.find('CDP'):].strip()[:80]
        elif 'NTP' in line:
            protocol = 'NTP'
            packet_info = line[line.find('NTP'):].strip()[:80]
        elif 'Loopback' in line:
            protocol = 'LOOPBACK'
            packet_info = line[line.find('Loopback'):].strip()[:80]
        
        # Build event
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_info": packet_info,
            "tcp_flags": tcp_flags,
            "activity_type": "network",
            "source": self.source,
            "week": self.week,
            "day": self.day,
            "category": "unknown"
        }
        
        # Remove None values for cleaner JSON
        if event["src_port"] is None:
            del event["src_port"]
        if event["dst_port"] is None:
            del event["dst_port"]
        if event["tcp_flags"] is None:
            del event["tcp_flags"]
        
        return event


def parse_all_tcpdump():
    base_path ="~/Downloads/cybersec-dataset/darpa"
    years = ["1999","1998"]
    weeks = ["week1", "week2", "week3", "week4", "week5"]
    days = ["monday", "tuesday", "wednesday", "thursday", "friday"]
    input_files =["inside.tcpdump.log", "outside.tcpdump.log"]
    output_file_prefix="parsed_"
    output_file_suffix=".jsonl"

    base_path = os.path.expanduser(base_path)
    for year in years:
        year_path = os.path.join(base_path, year)
        if not os.path.exists(year_path): continue
        for week in weeks:
            week_path = os.path.join(year_path, week)
            if not os.path.exists(week_path): continue
            for day in days:
                day_path = os.path.join(week_path, day)
                if not os.path.exists(day_path): continue
                for input_file in input_files:
                    input_file_path = os.path.join(day_path, input_file)
                    if not os.path.exists(input_file_path): continue
                    if os.path.getsize(input_file_path) == 0: continue
                    source_type = f"darpa{year}"
                    parser = SimpleTCPDumpParser(source=source_type,week=week,day=day)
                    print(input_file_path)
                    events = parser.parse_file(filepath=input_file_path,limit=None)
                    output_file_path = os.path.join(day_path, f"{output_file_prefix}{input_file}{output_file_suffix}")
                    print(output_file_path)
                    save_json(output_file=output_file_path,events=events)


def save_json(output_file,events):
    with open(output_file, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')

if __name__ == "__main__":
    parse_all_tcpdump()

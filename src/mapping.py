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

# Mapping of suspicious command / process categories
COMMAND_PATTERNS = {
    # Credential Access (T1110)
    'sshpass': 'credential_bruteforce',
    'hydra': 'credential_bruteforce',
    'sudo_bruteforce': 'credential_bruteforce',
    'credstuff': 'credential_stuffing',
    
    # Credential Dumping (T1003)
    'lsass': 'credential_dumping',
    'procdump': 'credential_dumping',
    'mimikatz': 'credential_dumping',
    'sekurlsa': 'credential_dumping',
    'reg export': 'credential_dumping',
    'reg save': 'credential_dumping',
    'MiniDump': 'credential_dumping',
    'comsvcs': 'credential_dumping',
    'NPPSpy': 'credential_dumping',
    
    # Defense Evasion (T1027, T1070, T1112)
    'reg add': 'registry_modification',
    'reg delete': 'registry_modification',
    'Set-ItemProperty': 'registry_modification',
    'New-ItemProperty': 'registry_modification',
    'Clear-History': 'clear_history',
    'wevtutil': 'clear_logs',
    'netsh firewall': 'firewall_disable',
    'Set-MpPreference': 'defender_disable',
    
    # Discovery (T1082, T1083, T1016, T1057, T1033)
    'find / -name': 'file_discovery',
    'Get-ChildItem': 'file_discovery',
    'ls': 'file_discovery',
    'dir': 'file_discovery',
    'whoami': 'user_discovery',
    'ipconfig': 'network_discovery',
    'ifconfig': 'network_discovery',
    'netstat': 'network_discovery',
    'Get-NetTCPConnection': 'network_discovery',
    'ps aux': 'process_discovery',
    'get-process': 'process_discovery',
    'tasklist': 'process_discovery',
    'systeminfo': 'system_discovery',
    'hostname': 'system_discovery',
    'nltest': 'domain_discovery',
    'gpresult': 'group_discovery',
    'groups': 'group_discovery',
    'Get-SmbShare': 'share_discovery',
    'Get-WmiObject': 'wmi_discovery',
    'wmic': 'wmi_discovery',
    
    # Lateral Movement (T1021)
    'MMC20.application': 'dcom_lateral',
    'plink.exe': 'ssh_lateral',
    'Connect-VIServer': 'vmware_lateral',
    'net use': 'smb_lateral',
    
    # Persistence (T1098, T1136, T1543, T1547)
    'useradd': 'account_creation',
    'pw adduser': 'account_creation',
    'authorized_keys': 'ssh_key_persistence',
    'schtasks': 'scheduled_task',
    'sc.exe': 'service_creation',
    'Winlogon': 'winlogon_persistence',
    'STARTUP-PATH': 'office_persistence',
    
    # Command Execution (T1059)
    'mktemp': 'script_execution',
    'bash': 'script_execution',
    'powershell': 'script_execution',
    'cmd.exe': 'script_execution',
    'IEX': 'script_execution',
    'Invoke-Expression': 'script_execution',
    'python': 'script_execution',
    
    # File Download/Transfer (T1105)
    'curl': 'file_download',
    'wget': 'file_download',
    'bitsadmin': 'bits_transfer',
    'certutil': 'certutil_download',
    'Invoke-WebRequest': 'web_request',
    
    # DoS/Impact (T1498, T1499)
    'hping3': 'dos_attack',
    'slowhttptest': 'dos_attack',
    'timeout': 'dos_attack',
    'vssadmin': 'shadow_copy_delete',
    'wbadmin': 'backup_delete',
    'bcdedit': 'boot_modification',
    'shutdown': 'system_shutdown',
    
    # Exfiltration (T1041, T1560)
    'curl -F': 'data_exfiltration',
    'tar -zcf': 'data_compression',
    'Compress-Archive': 'data_compression',
    'file/upload': 'data_upload',
    
    # Obfuscation (T1027)
    'EncodedCommand': 'obfuscated_command',
    'obfuscated': 'obfuscated_command',
    'encoded': 'obfuscated_command',
    
    # Proxy Execution (T1218)
    'mshta': 'mshta_execution',
    'regsvr32': 'regsvr32_execution',
    'rundll32': 'rundll32_execution',
    'odbcconf': 'odbcconf_execution',
    'mavinject': 'mavinject_injection',
    
    # C2 (T1071, T1095)
    'powercat': 'powercat_c2',
    'dnscat2': 'dnscat_c2',
    'Invoke-PowerShellIcmp': 'icmp_c2',
    
    # UAC Bypass (T1548)
    'mscfile': 'uac_bypass',
    
    # Process Injection (T1055)
    'INJECTRUNNING': 'process_injection',
    
    # Network Scanning (T1046)
    'Scan-Netrange': 'network_scanning',
    'nmap': 'network_scanning',
    
    # Bits Jobs (T1197)
    'bitsadmin /create': 'bits_job_creation',
    'bitsadmin /transfer': 'bits_transfer'
}

PROCESS_PATTERNS = {
    # Credential Access (T1110)
    'sshpass': 'credential_bruteforce',
    'hydra': 'credential_bruteforce',
    
    # Credential Dumping (T1003)
    'procdump': 'credential_dumping',
    'mimikatz': 'credential_dumping',
    'lsass': 'credential_dumping',  # Note: lsass is a process
    
    # Defense Evasion (T1027, T1070, T1112)
    'powershell': 'script_execution',
    'cmd.exe': 'script_execution',
    'bash': 'script_execution',
    'python': 'script_execution',
    
    # Discovery (T1082, T1083, T1016, T1057, T1033)
    'whoami': 'user_discovery',
    'ipconfig': 'network_discovery',
    'ifconfig': 'network_discovery',
    'netstat': 'network_discovery',
    'tasklist': 'process_discovery',
    'systeminfo': 'system_discovery',
    'hostname': 'system_discovery',
    'nltest': 'domain_discovery',
    'gpresult': 'group_discovery',
    'groups': 'group_discovery',
    'wmic': 'wmi_discovery',
    
    # Lateral Movement (T1021)
    'plink.exe': 'ssh_lateral',
    
    # Persistence (T1098, T1136, T1543, T1547)
    'schtasks': 'scheduled_task',
    'sc.exe': 'service_creation',
    
    # File Download/Transfer (T1105)
    'curl': 'file_download',
    'wget': 'file_download',
    'bitsadmin': 'bits_transfer',
    'certutil': 'certutil_download',
    
    # DoS/Impact (T1498, T1499)
    'hping3': 'dos_attack',
    'slowhttptest': 'dos_attack',
    'vssadmin': 'shadow_copy_delete',
    'wbadmin': 'backup_delete',
    'bcdedit': 'boot_modification',
    'shutdown': 'system_shutdown',
    
    # Exfiltration (T1041, T1560)
    'tar': 'data_compression',
    
    # Proxy Execution (T1218)
    'mshta': 'mshta_execution',
    'regsvr32': 'regsvr32_execution',
    'rundll32': 'rundll32_execution',
    'odbcconf': 'odbcconf_execution',
    'mavinject': 'mavinject_injection',
    
    # C2 (T1071, T1095)
    'powercat': 'powercat_c2',
    'dnscat2': 'dnscat_c2',
    
    # Network Scanning (T1046)
    'nmap': 'network_scanning'
}


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
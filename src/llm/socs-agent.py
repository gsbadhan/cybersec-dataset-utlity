import sys
sys.path.insert(0,"./src")
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY
from langchain_core.messages import SystemMessage, HumanMessage
from collections import defaultdict
import csv
import json

_ALPHA=0.3
_BETA=0.7
_GAMMA=0.5
_MITRE_TACTIC_TO_TECHNIQUE= defaultdict(set)
_MITRE_TECHNIQUE_TO_SUBTECHNIQUE= defaultdict(set)

llm1 = ChatOpenAI(
    model="gpt-5.4-mini-2026-03-17",
    temperature=0,
    max_completion_tokens=200,
    verbosity="low",
    frequency_penalty=0.5,
    presence_penalty=0.5,
    openai_api_key=OPENAI_API_KEY,
)

llm2 = ChatOpenAI(
    model="gpt-5.4-mini-2026-03-17",
    temperature=0,
    max_completion_tokens=200,
    verbosity="low",
    frequency_penalty=0.5,
    presence_penalty=0.5,
    openai_api_key=OPENAI_API_KEY,
)

def build_attack_dictionaries():
    global _MITRE_TACTIC_TO_TECHNIQUE
    global _MITRE_TECHNIQUE_TO_SUBTECHNIQUE
    mitre_file= "/Users/gurpreetsingh/Downloads/cybersec-dataset/cybersec-dataset-utlity/mitre_tactic_technique.csv"
    with open(mitre_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            tactic_id = row['tactic_id']
            technique_id = row['technique_id']
            
            # Extract base technique ID (remove everything after '.')
            base_technique = technique_id.split('.')[0]
            
            # Add mapping: tactic_id -> base_technique
            _MITRE_TACTIC_TO_TECHNIQUE[tactic_id].add(base_technique)
            
            # If it's a sub-technique, map base -> sub
            _MITRE_TECHNIQUE_TO_SUBTECHNIQUE[base_technique].add(technique_id)
    
    # Convert sets to sorted lists for cleaner output
    _MITRE_TACTIC_TO_TECHNIQUE = {
        tactic: sorted(list(techs)) 
        for tactic, techs in _MITRE_TACTIC_TO_TECHNIQUE.items()
    }
    
    _MITRE_TECHNIQUE_TO_SUBTECHNIQUE = {
        tech: sorted(list(subs))
        for tech, subs in _MITRE_TECHNIQUE_TO_SUBTECHNIQUE.items()
    }
    # print(f"_MITRE_TACTIC_TO_TECHNIQUE {_MITRE_TACTIC_TO_TECHNIQUE}")
    # print(f"_MITRE_TECHNIQUE_TO_SUBTECHNIQUE {_MITRE_TECHNIQUE_TO_SUBTECHNIQUE}")
    

""" generate attack hypothesis based on security event"""
def llm_call_1(security_event:dict):
    system_prompt = "You are a cybersecurity expert."
    user_prompt = f"""
                Analyze this security event and identify the MITRE ATT&CK technique or possible list of MITRE ATT&CK techniques. NO explanation, No reasoning.
                Event Details:
                {str(security_event)}
                Respond ONLY with below fields if you have correct answer:
                Technique ID: TXXXX
                Technique Name: XXXXX
                Tectic ID: TAXXXXX
                Tectic Name: TAXXXXX
                Sub Technique ID: TXXXX
                Sub Technique Name: TXXXX

                OR

                Respond ONLY with below fields if you have None or empty value any of them:
                Technique ID: ""
                Technique Name: ""
                Tectic ID: ""
                Tectic Name: ""
                Sub Technique ID: ""
                Sub Technique Name: ""
                
                Dont skip any field if value not found, all fields are must part of response.
                
                The response format must be in JSON as per below examples:
                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1087",
                "technique_name": "Account Discovery",
                "sub_technique_id": "T1087.001",
                "sub_technique_name": "Account Discovery: Local Account"

                OR

                "tactic_id": "TA0007",
                "tactic_name": "Discovery",
                "technique_id": "T1087",
                "technique_name": "Account Discovery",
                "sub_technique_id": "",
                "sub_technique_name": ""

                """
    print(f"prompt={user_prompt}")
    response = llm1.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    print(f"llm response {response}")
    attack_hypoths= json.loads(response.content)
    print(f"Agent Response={attack_hypoths}")
    return attack_hypoths

""" validate list of attack hypotheis """    
def validate_attack_hypoths(attack_hypoths:dict):
    # Extract base technique ID (remove everything after '.')
    technique_id = attack_hypoths["technique_id"].split('.')[0]
    if attack_hypoths["tactic_id"] in _MITRE_TACTIC_TO_TECHNIQUE:
        if technique_id in _MITRE_TECHNIQUE_TO_SUBTECHNIQUE:
            return attack_hypoths

def compute_ssim(securty_event:dict, attack_hypoths:dict):
    return 0.33

def compute_sagr(attack_hypoths:dict):
    return 0.88

def compute_sevd(securty_event:dict, attack_hypoths:dict):
    evidence=["encoded_command"]
    return (0.8, evidence)


""" compute confidence factor for each attack and return highest one """
def compute_confidence_factor(securty_event:dict, attack_hypoths:dict):
    sevd= compute_sevd(securty_event=securty_event, attack_hypoths=attack_hypoths)
    confidence= (_ALPHA * compute_ssim(securty_event=securty_event,attack_hypoths=attack_hypoths)) 
    + (_BETA * compute_sagr(attack_hypoths=attack_hypoths)) 
    + (_GAMMA * sevd[0])
    evidence= sevd[1]
    hsc_attack_hypoths = (attack_hypoths, confidence, evidence)
    #print(hsc_attack_hypoths)
    return hsc_attack_hypoths

""" generate explanation based on facts"""
def llm_call_2(security_event:dict, hsc_attack_hypoths:tuple):
    attack_hypoths= hsc_attack_hypoths[0]
    confidence= hsc_attack_hypoths[1]
    evidence= hsc_attack_hypoths[2]

    system_prompt = "You are a cybersecurity expert."
    user_prompt = f""" 
                   Generate human readable explanation using below given facts. The explanation not more than 100 words. Make sure that explanation understandable by security operations team.
                   security event = {str(security_event)}
                   MITRE ATT&CK hypothesis = {attack_hypoths} 
                   confidence score in % based on security event evaluation= {confidence}
                   list of activities as evidence = {evidence}
                """
    print(f"prompt={user_prompt}")
    response = llm2.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    print(f"llm response=\n{response}")
    print(f"Agent Response=\n{response.content}")
    return ""

def end_to_end_call():
    build_attack_dictionaries()
    event= r"""{"event": {"id": "61c162ed-52c9-4c8c-a32d-5edb90f6f34a", "timestamp": "2026-05-03T03:30:49Z", "type": ["endpoint", "process"], "category": ["host", "process"], "enrichment_sources": ["mitreTTP", "assetDB", "geoIP"], "source": "caldera"}, "network": {"protocol": "", "transport":
"", "direction": "", "packets": 0, "bytes": 0}, "source": {"ip": "192.168.2.36", "port": 0, "address": "", "geo_ip": {"country_iso_code": "IND", "country_name": "India",
"state": "Delhi", "city": "Delhi", "is_private": true, "timezone": "IST"}, "asset": {"asset_type": "workstation", "criticality": "high", "owner": "", "hostname": "mac", "
os": "mac", "location": "", "is_external": false}}, "destination": {"ip": "10.0.2.15", "port": 0, "address": "", "geo_ip": {"country_iso_code": "IND", "country_name": "In
dia", "state": "Delhi", "city": "Delhi", "is_private": true, "timezone": "IST"}, "asset": {"asset_type": "workstation", "criticality": "high", "owner": "", "hostname": "u
buntu-vb", "os": "linux", "location": "", "is_external": false}}, "host": {"user": "ubuntu", "hostname": "ubuntu-vb", "group": "red", "platform": "linux", "architecture":
 "amd64"}, "process": {"pid": 1994, "ppid": 0, "name": "mkdir", "command_line": "mkdir -p staged && echo $PWD/staged", "executor": "sh", "user": "ubuntu", "host": "ubuntu
-vb", "exit_code": -1, "status": "success"}"""
    #print(event)
    attack_hypoths= llm_call_1(security_event=event)
    if attack_hypoths is None:
        print(f"llm  attack_hypoths not fond {attack_hypoths} !!")
        return
    valid_attack_hypths= validate_attack_hypoths(attack_hypoths=attack_hypoths)
    if valid_attack_hypths is None:
        print(f"validate_attack_hypoths not fond {valid_attack_hypths} !!")
        return
    
    hsc_attack_hypoths= compute_confidence_factor(securty_event=event,attack_hypoths=valid_attack_hypths)
    final_response= llm_call_2(security_event=event, hsc_attack_hypoths=hsc_attack_hypoths)


if __name__ == "__main__":
    end_to_end_call()

    
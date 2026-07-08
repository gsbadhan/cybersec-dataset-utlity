import sys
sys.path.insert(0,"./src")
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY
from langchain_core.messages import SystemMessage, HumanMessage


llm = ChatOpenAI(
    model="gpt-5.4-mini-2026-03-17",
    temperature=0,
    max_completion_tokens=200,
    verbosity="low",
    frequency_penalty=0.5,
    presence_penalty=0.5,
    openai_api_key=OPENAI_API_KEY,
)



""" generate explanation based on facts"""
def llm_call(security_event:dict, attack_hypoths:dict):
    confidence= 0.89
    evidence= ["directory_creation"]

    system_prompt = "You are a cybersecurity expert."
    user_prompt = f""" 
                   Generate human readable explanation using below given facts. The explanation not more than 100 words. Make sure that explanation understandable by security operations team.
                   security event = {str(security_event)}
                   MITRE ATT&CK hypothesis = {attack_hypoths} 
                   confidence score in % based on security event evaluation= {confidence}
                   list of activities as evidence = {evidence}
                """
    print(f"prompt={user_prompt}")
    response = llm.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    print(f"llm response=\n{response}")
    print(f"Agent Response=\n{response.content}")
    return ""

def end_to_end_call():
    
    event= r"""{"event": {"id": "61c162ed-52c9-4c8c-a32d-5edb90f6f34a", "timestamp": "2026-05-03T03:30:49Z", "type": ["endpoint", "process"], "category": ["host", "process"], "enrichment_sources": ["mitreTTP", "assetDB", "geoIP"], "source": "caldera"}, "network": {"protocol": "", "transport":
"", "direction": "", "packets": 0, "bytes": 0}, "source": {"ip": "192.168.2.36", "port": 0, "address": "", "geo_ip": {"country_iso_code": "IND", "country_name": "India",
"state": "Delhi", "city": "Delhi", "is_private": true, "timezone": "IST"}, "asset": {"asset_type": "workstation", "criticality": "high", "owner": "", "hostname": "mac", "
os": "mac", "location": "", "is_external": false}}, "destination": {"ip": "10.0.2.15", "port": 0, "address": "", "geo_ip": {"country_iso_code": "IND", "country_name": "In
dia", "state": "Delhi", "city": "Delhi", "is_private": true, "timezone": "IST"}, "asset": {"asset_type": "workstation", "criticality": "high", "owner": "", "hostname": "u
buntu-vb", "os": "linux", "location": "", "is_external": false}}, "host": {"user": "ubuntu", "hostname": "ubuntu-vb", "group": "red", "platform": "linux", "architecture":
 "amd64"}, "process": {"pid": 1994, "ppid": 0, "name": "mkdir", "command_line": "mkdir -p staged && echo $PWD/staged", "executor": "sh", "user": "ubuntu", "host": "ubuntu
-vb", "exit_code": -1, "status": "success"}"""
    #print(event)
    attack_hypoths= {
                "tactic_id": "TA0009",
                "tactic_name": "Collection",
                "technique_id": "T1074",
                "technique_name": "Data Staged",
                "sub_technique_id": "T1074 .001",
                "sub_technique_name": "Data Staged: Local data staging"
                }
    if attack_hypoths is None:
        print(f"llm  attack_hypoths not fond {attack_hypoths} !!")
        return
    
    final_response= llm_call(security_event=event, attack_hypoths=attack_hypoths)


if __name__ == "__main__":
    end_to_end_call()

    
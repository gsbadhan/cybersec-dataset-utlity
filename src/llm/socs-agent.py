import sys
sys.path.insert(0,"./src")
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY
import re
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


def llm_call_1(security_event:str):
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
    response = llm.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    print(f"llm response {response}")
    print(f"Agent Response={response.content}")

    return response.content
    

def llm_call_2(security_event:str, attack_hypoths:dict):
    confidence=0.89
    evidence=["encoded_command"]

    system_prompt = "You are a cybersecurity expert."
    user_prompt = f""" 
                   Generate human readable explanation using below given facts. The explanation not more than 100 words. Make sure that explanation understandable by security operations team.
                   security event = {str(security_event)}
                   MITRE ATT&CK hypotheis = {attack_hypoths} 
                   confidence score based on security event evaluation= {confidence}
                   list of activity evidence = {evidence}
                """
    print(f"prompt={user_prompt}")
    response = llm.invoke([SystemMessage(system_prompt), HumanMessage(user_prompt)])
    print(f"llm response=\n{response}")
    print(f"Agent Response=\n{response.content}")
    return ""


if __name__ == "__main__":
    event= """{"@timestamp":"2026-05-03T03:29:51.000Z","event":{"id":"evt-8939bc01547de8402cedb0019c84e852","kind":"alert","category":["host","process","intrusion_detection"],"type":["process_creation","discovery","reconnaissance"],"severity":5,"action":"process_execution","enriched_at":"2026-05-03T03:30:26.000Z","enrichment_sources":["caldera","asset_db"]},"network":{"protocol":"tcp","transport":"tcp","direction":"egress","packets":1,"bytes":60},"source":{"ip":"10.0.2.15","port":2827,"address":"10.0.2.15","geo_ip":{"country_iso_code":"PRIVATE","country_name":"Private/RFC1918","location_type":"private","is_private":true},"asset":{"asset_type":"workstation","criticality":"HIGH","owner":"CORP\\Terminaluser","hostname":"TLPORT-PC-11","os":"Windows 10","location":"inside_network"}},"destination":{"ip":"10.0.2.15","port":80,"address":"10.0.2.15","geo_ip":{"country_iso_code":"PRIVATE","country_name":"Private/RFC1918","location_type":"private","is_private":true},"asset":{"asset_type":"workstation","criticality":"HIGH","is_external":false,"owner":"CORP\\Terminaluser","hostname":"TLPORT-PC-11"}},"tcp":{"flags":"SYN","seq":0,"window":512,"mss":1460},"process":{"pid":3728,"ppid":3312,"name":"powershell.exe","command_line":"powershell -EncodedCommand AHkAIABVAG4AZABlHDJKNLKJNK879JCNN","executor":"psh","user":"CORP\\Terminaluser","host":"TLPORT-PC-11","platform":"windows"}}"""
    #print(event)
    attack_hypoths= llm_call_1(security_event=event)
    final_response= llm_call_2(security_event=event, attack_hypoths=attack_hypoths)


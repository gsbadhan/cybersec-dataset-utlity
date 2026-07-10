### convert caldera event json file to normalised json file

import json
from config import CALDERA, OUTPUT
from mapping import extract_process_name, init_mappings,MITRE_TECHNIQUEID_TO_TECHNIQUENAME, MITRE_TACTICNAME_TO_TACTICID, HOST_TO_IP, LOG_SOURCES, ASSET_TYPE, PRIORITY
from security_event import SecurityEvent, Event, Network, Source, Destination, Mitre, Host, Process, Asset, GeoIP
import uuid

tactics= set()

""" parse raw events from path config.CALDERA.raw_event_json """
def parse_caldera_flat(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    events = []

    for item in data:
         tactics.add(item.get("attack_metadata", {}).get("tactic"))
         technique_ids= item.get("attack_metadata", {}).get("technique_id").split('.')
         technique_id= technique_ids[0] 
         sub_technique_id= item.get("attack_metadata", {}).get("technique_id") if len(technique_ids)>1 else ""
         technique_names= item.get("attack_metadata", {}).get("technique_name").split(':')
         technique_name= technique_names[0]
         sub_technique_name= item.get("attack_metadata", {}).get("technique_name") if len(technique_names)>1 else ""
         evt = SecurityEvent(
             host= Host(
                 user=item.get("agent_metadata", {}).get("username"),
                 hostname=item.get("agent_metadata", {}).get("host"),
                 group=item.get("agent_metadata", {}).get("group"),  
                 platform=item.get("platform"), 
                 architecture=item.get("agent_metadata", {}).get("architecture")),
             network=Network(),
             source=Source(ip=HOST_TO_IP.get("src"), 
                           asset= Asset(asset_type=ASSET_TYPE[0], 
                                        criticality=PRIORITY[0], 
                                        os="mac", 
                                        hostname="mac"),
                           geo_ip=GeoIP()
                           ),
             destination=Destination(ip=HOST_TO_IP.get(item.get("agent_metadata", {}).get("host")),
                                     asset= Asset(asset_type=ASSET_TYPE[0], 
                                                  criticality=PRIORITY[0], 
                                                  os=item.get("platform"), 
                                                  hostname=item.get("agent_metadata", {}).get("host")),
                                     geo_ip=GeoIP()
                                     ),
             process=Process(pid=item.get("pid", 0) if item.get("pid") is not None else 0,
                             user=item.get("agent_metadata", {}).get("username"),
                             host=item.get("agent_metadata", {}).get("host"),
                             command_line=item.get("command"),
                             name= extract_process_name(item.get("command")),
                             executor=item.get("executor"),
                             exist_code=item.get("status", -1),
                             status="success" if item.get("status") == 0 else "failed"),
             mitre=[Mitre(tactic_id=MITRE_TACTICNAME_TO_TACTICID[item.get("attack_metadata", {}).get("tactic")] if item.get("attack_metadata", {}).get("tactic") in MITRE_TACTICNAME_TO_TACTICID else "",
                          tactic_name=item.get("attack_metadata", {}).get("tactic"),
                          technique_id=technique_id,
                          technique_name=technique_name,
                          sub_technique_id= sub_technique_id,
                          sub_technique_name=sub_technique_name
                          )],
             event=Event(id=str(uuid.uuid4()),
                         timestamp=item.get("finished_timestamp"),
                         type=["endpoint", "process"], 
                         activity=[MITRE_TECHNIQUEID_TO_TECHNIQUENAME[technique_id]], 
                         category=["host", "process"], 
                         enrichment_sources=["mitreTTP","assetDB", "geoIP"], 
                         source=LOG_SOURCES["CALDERA"])
             )
         
         events.append(evt)

    return events


#
def save_events(events, path):
    events_dict = [event.to_dict() for event in events]
    with open(path, "w") as f:
        json.dump(events_dict, f, default=str)


###
# merge json files jq -s 'add' *.json > raw_events.json 
init_mappings()
events = parse_caldera_flat(CALDERA.get("raw_event_json"))
print(events[0])
print (len(events))
save_events(events=events, path=OUTPUT.get("caldera_events"))
print(f"tactics= {tactics}")


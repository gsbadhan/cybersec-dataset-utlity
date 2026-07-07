import sys
sys.path.insert(0,"./src")
import json
import os
from config import OUTPUT

llm_train_file=OUTPUT.get("llm_train_dataset")
caledra_file=OUTPUT.get("caldera_events")
splunk_security_file=OUTPUT.get("splunk_detection_events")

events_per_dataset=100;

#read caldera events
def read_caldera(input_file,output_file):
    data=[]

    with open(file=input_file, mode='r', encoding='utf-8') as f:
        data = json.load(f)

    buffer= []
    events_counter= 0
    for row in data:
        log={
            "activity": row["command"],
            "activity_type": "command",
            "platform": row["platform"],
            "executor": row["executor"],
            "tactic_id": row["tactic_id"],
            "tactic_name": row["tactic_name"],
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "sub_technique_id": row["sub_technique_id"],
            "sub_technique_name": row["sub_technique_name"]
        }
        buffer.append(log)
        if (len(buffer) % 100) ==0 and events_counter <=events_per_dataset:
            write_file(buffer,output_file=output_file)
            events_counter+=len(buffer)
            buffer=[]

    if len(buffer) >0 and events_counter <=events_per_dataset:
        write_file(buffer,output_file=output_file)

#read splunk events
def read_splunk(input_file,output_file):

    buffer =[]
    events_counter= 0
    with open(file=input_file, mode='r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                row= json.loads(line)
                log={
                    "activity": row["search_query"],
                    "activity_type": "NA",
                    "platform": row["security_domain"],
                    "executor": "NA",
                    "technique_id": row["mitre_technique_ids"][0] if row["mitre_technique_ids"] else "NA"
                }
                buffer.append(log)
                if (len(buffer) % 100) == 0 and events_counter <=events_per_dataset:
                    write_file(buffer,output_file=output_file)
                    events_counter+=len(buffer)
                    buffer=[]

    if len(buffer) >0 and events_counter <=events_per_dataset:
        write_file(buffer,output_file=output_file)        




def write_file(rows,output_file):
    with open(output_file, "a") as f:
        for row in rows:
            f.write(json.dumps(row)+ "\n")

def delete_file(file_path):    
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File {file_path} deleted successfully")
    else:
        print(f"File {file_path} does not exist")

### run
delete_file(file_path=llm_train_file)
read_caldera(input_file=caledra_file, output_file=llm_train_file)
#read_splunk(input_file=splunk_security_file, output_file=llm_train_file)
print("done..")
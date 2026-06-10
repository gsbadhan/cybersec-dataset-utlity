import sys
sys.path.insert(0,"./src")

from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from pymongo import MongoClient
import json
import re


client = MongoClient("mongodb://localhost:27017")
db = client["cybersec"]

##

#llm = ChatOllama(model="deepseek-r1:8b", temperature=0, num_predict=100)

# llm = ChatOpenAI(
#     model="gpt-5.4-mini-2026-03-17",
#     temperature=0,
#     max_completion_tokens=50,
#     verbosity="low",
#     frequency_penalty=0.5,
#     presence_penalty=0.5,
#     openai_api_key="YOUR_OPENAI_KEY_HERE",
# )

# llm = ChatOpenAI(
#     model="deepseek-v4-flash",              
#     openai_api_key="xxx",
#     base_url="https://api.deepseek.com/v1",  
#     temperature=0,                           
#     max_tokens=50,                           
#     frequency_penalty=0.5,
#     presence_penalty=0.5,
# )


def extract_data(database, collection_name="caldera_events",sample_size=1):
        docs=[]
        collection=database[collection_name]
        print(f"fetching data from {collection_name}..")
        cursor = collection.aggregate([
                    {
                        "$match": {
                            "technique_id": {"$exists": True}
                        }
                    },
                    {
                        "$sample": {
                            "size": sample_size
                        }
                    },
                    {
                        "$project": {
                            "_id": 0,
                            "host": 1,
                            "agent_id":1,
                            "username":1,
                            "platform":1,
                            "executor":1,
                            "command":1,
                            "exit_code":1,
                            "status":1,
                            "activity_type":1,
                            "category":1,
                            "src_ip":1,
                            "dst_ip":1,
                            "technique_id": 1
                        }
                    }
                ])

        for doc in cursor:
            docs.append(doc)
            
        return docs;
        

def hit_llm(docs):
    stats={}
    counter= 0
    for doc in docs:
            counter = counter +1
            ground_truth_id = doc.get("technique_id")
            event_for_analysis = {k: v for k, v in doc.items() 
                              if k not in ["technique_id"]}
            #print(f"{event_for_analysis}")
            prompt = f"""
                        You are a cybersecurity expert. Analyze this security event and identify the MITRE ATT&CK technique or possible list of MITRE ATT&CK techniques. NO explanation, No reasoning.

                        Event Details:
                        {str(event_for_analysis)}

                        Respond ONLY in this format if you have correct answer:
                        Technique ID: [TXXXX]
                        
                        OR

                        Respond ONLY in this format if you have None or empty:
                        Technique ID: []
                        """
            #print(f"prompt={prompt}")
            response = llm.invoke(prompt)
            print(f"llm response {response}")
            print(f"Agent Response={response.content}, actual_id={ground_truth_id}")
            match = re.search(r"Technique ID:\s*\[?(T\d+)\]?", response.content)
            predicted_id = match.group(1) if match else None
            print(f"Agent Response={response.content}, actual_id={ground_truth_id}, predicted_id={predicted_id}, counter={counter}")
            
            if ground_truth_id not in stats:
                  stats[ground_truth_id] = {"matched": 0, "missed": 0}

            if predicted_id and predicted_id == ground_truth_id:
                  stats[ground_truth_id]["matched"] += 1
            else:
                  stats[ground_truth_id]["missed"] += 1

        ##
    print(f"stats={stats}")
    return stats;                  


def get_percentage_summary(stats):
    """Return percentage summary as dictionary"""
    summary = {}
    
    for technique_id, counts in stats.items():
        total = counts["matched"] + counts["missed"]
        summary[technique_id] = {
            "matched": counts["matched"],
            "missed": counts["missed"],
            "total": total,
            "accuracy_percent": round((counts["matched"] / total * 100), 1) if total > 0 else 0
        }
    
    total_matched = sum(counts["matched"] for counts in stats.values())
    total_missed = sum(counts["missed"] for counts in stats.values())
    total_events = total_matched + total_missed
    
    summary["overall"] = {
        "matched": total_matched,
        "missed": total_missed,
        "total": total_events,
        "accuracy_percent": round((total_matched / total_events * 100), 1) if total_events > 0 else 0
    }
    
    return summary


### run
docs=extract_data(database=db,sample_size=10000)
stats=hit_llm(docs=docs)
summary=get_percentage_summary(stats)
print(summary)

import sys
sys.path.insert(0,"./src")

from pymongo import MongoClient
import config
import json
from typing import Dict

ATTACK_TYPES = [
  'benign',  
  'Bot',
  'DDoS',
  'DoS GoldenEye',
  'DoS Hulk',
  'DoS Slowhttptest',
  'DoS slowloris',
  'FTP-Patator',
  'Heartbleed',
  'Infiltration',
  'PortScan',
  'SSH-Patator'
]

class CicEvents:

    def __init__(self):
        self.client = MongoClient(host="localhost", port=27017)
        print(f"connected at {self.client}")


    def get_or_create_database(self, db_name="cybersec"):
        print(f"databases {self.client.list_database_names()}")
        exist = db_name in self.client.list_database_names()
        if exist:
            print(f"{db_name} exist")
        else:
            print(f"{db_name} not exist")

        db = self.client[db_name]
        print(f"collections {db.list_collection_names()}")
        return db

    def read_json(self, file_path):
        data = []
        with open(file=file_path, mode='r') as f:
            content = f.read().strip()
            lines = content.split('\n')
            for line in lines:
                data.append(line.strip())
            return data
        

    def clean_record(self, record: Dict) -> Dict:
        cleaned = {}
        for key, value in record.items():
            if value == "" or value == [] or value == {}:
                continue
            elif isinstance(value, dict):
                nested_cleaned = self.clean_record(value)
                if nested_cleaned:
                    cleaned[key] = nested_cleaned
            else:
                cleaned[key] = value
        return cleaned
    
    def create_bulk_record(self, database="cybersec", collection_name="cic_events",  delete_collection=False):
        cic_events_file = config.OUTPUT.get("cic_events")
        collection=database[collection_name]
            
        if delete_collection:
            collection.drop()
            print(f"{collection_name} collection deleted")
        
        records = self.read_json(file_path=cic_events_file)
        print(f"{len(records)} records found in file")

        for record in records:
            json_record = json.loads(record)
            mongo_record=self.clean_record(json_record)
            collection.insert_one(mongo_record)
        
        total_count = collection.count_documents({})
        print(f"{total_count} records found in collection {collection_name}")

        # indexes
        collection.create_index('event_id', unique=True)    

    def extract_data_for_ML(self, database, collection_name="cic_events",sample_size=1):
        collection=database[collection_name]
        print(f"fetching data from {collection_name}..")
        cic_ml_file=config.OUTPUT.get("cic_ml")
        with open(cic_ml_file,"w") as f:
            for attack in ATTACK_TYPES:
                cursor = collection.aggregate([
                    {
                        "$match": {
                            "technique_id": {"$exists": True},
                            "attack_type": attack
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
                            "flow_features": 1,
                            "technique_id": 1
                        }
                    }
                ])

                for doc in cursor:
                    f.write(json.dumps(doc)+"\n")



if __name__ == "__main__":
    cic = CicEvents()
    db=cic.get_or_create_database(db_name="cybersec")
    #cic.create_bulk_record(database=db, delete_collection=True)
    #cic.extract_data_for_ML(database=db, sample_size=50000)
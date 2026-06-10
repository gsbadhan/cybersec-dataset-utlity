import sys
sys.path.insert(0,"./src")

from pymongo import MongoClient
import config
import json
from typing import Dict

class SnortRules:

    def __init__(self):
        self.client = MongoClient(host="localhost", port=27017)
        print(f"connected at {self.client}")


    def get_or_create_database(self, db_name):
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
    
    def create_bulk_record(self, database, collection_name="snort_rules",  delete_collection=False):
        snort_file = config.OUTPUT.get("snort_rules")
        collection=database[collection_name]
            
        if delete_collection:
            collection.drop()
            print(f"{collection_name} collection deleted")
        
        records = self.read_json(file_path=snort_file)
        print(f"{len(records)} records found in file")

        for record in records:
            json_record = json.loads(record)
            mongo_record=self.clean_record(json_record)
            collection.insert_one(mongo_record)
        
        total_count = collection.count_documents({})
        print(f"{total_count} records found in collection {collection_name}")

        # indexes
        collection.create_index('sid', unique=True)    


if __name__ == "__main__":
    snort = SnortRules()
    db=snort.get_or_create_database(db_name="cybersec")
    snort.create_bulk_record(database=db, delete_collection=True)
from typing import List, Optional
from pydantic import BaseModel, Field


class GeoIP(BaseModel):
    country_iso_code: str = "IND" # US, IND
    country_name: str = "India" # India
    state: str = "Delhi"
    city: str = "Delhi"
    is_private: bool = True
    longitude: Optional[float] = 28.6687
    latitude: Optional[float] = 77.2304
    timezone: str = "IST" # IST


class Asset(BaseModel):
    asset_type: str = "" # workstation, web_server
    criticality: str = "" # HIGH, MEDIUM, LOW
    owner: str = ""
    hostname: str = ""
    os: str = ""
    location: str = "" # inside_network
    is_external: bool = False
    domain: Optional[str] = None
    
   

class TCP(BaseModel):
    flags: str = "" # SYN
    seq: int = 0
    window: int = 0
    mss: int = 0



class Network(BaseModel):
    protocol: str = "" # tcp, udp, http
    transport: str = "" # tcp, udp, http
    direction: str = "" # egress, ingress
    packets: int = 0
    bytes: int = 0
    tcp:TCP = None



class Source(BaseModel):
    ip: str = ""
    port: int = 0
    address: str = ""
    geo_ip: GeoIP = None
    asset: Asset = None


class Destination(BaseModel):
    ip: str = ""
    port: int = 0
    address: str = ""
    geo_ip: GeoIP = None
    asset: Asset = None


class Process(BaseModel):
    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    executor: str = "" # sh
    user: str = ""
    host: str = ""
    working_directory: Optional[str] = None
    parent_process_name: Optional[str] = None
    exit_code: int = -1
    status: str = ""


class Host(BaseModel):
    user: str = ""
    hostname: str = ""
    group: str = ""
    platform: str = "" # windows, mac, linux
    architecture: str = "" # amd64


class Mitre(BaseModel):
    tactic_id: str = ""
    tactic_name: str = ""
    technique_id: str = ""
    technique_name: str = ""
    sub_technique_id: str = ""
    sub_technique_name: str = ""


class Event(BaseModel):
    id: str = ""
    timestamp: Optional[str] = None
    type: List[str] = None # [alert, network, endpoint, process]
    activity: List[str] = None #["process_creation"]
    category: List[str] = None #["host", "process"]
    enrichment_sources: List[str] = None #["geoip","asset_db"]
    source:str

class Suspicious(BaseModel):
    commands: List[str]= None # ['find', 'hydra', 'sudo']
    processes: List[str]= None # ['sc.exe', 'cmd.exe']
    users: List[str]= None # ['johan', 'david van']
    IPs: List[str]= None # ['192.167.6.189']

class SecurityEvent(BaseModel):
    event:Event = Field(default_factory=Event)
    network: Network = Field(default_factory=Network)
    source: Source = Field(default_factory=Source)
    destination: Destination = Field(default_factory=Destination)
    host:Host = Field(default_factory=Host)
    process:Process= Field(default_factory=Process)
    suspicious:Suspicious= Field(default_factory=Suspicious)
    mitre:Optional[List[Mitre]] = Field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return self.model_dump(exclude_none=True)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return self.model_dump_json(indent=indent, exclude_none=True)

if __name__ == "__main__":
    print(SecurityEvent(event=Event(), network=Network(),source=Source(), destination=Destination(), host=Host(), mitre=None))    
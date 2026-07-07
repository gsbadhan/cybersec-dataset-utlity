from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class GeoIP(BaseModel):
    country_iso_code: str = "PRIVATE" # PRIVATE, PUBLIC
    country_name: str = "Private/RFC1918"
    location_type: str = "private"
    is_private: bool = True
    longitude: Optional[float] = None
    latitude: Optional[float] = None


class Asset(BaseModel):
    asset_type: str = "workstation"
    criticality: str = "MEDIUM" # HIGH, MEDIUM
    owner: str = ""
    hostname: str = ""
    os: str = ""
    location: str = "inside_network"
    is_external: bool = False
    domain: Optional[str] = None
   

class TCP(BaseModel):
    flags: str = "SYN"
    seq: int = 0
    window: int = 0
    mss: int = 0



class Network(BaseModel):
    protocol: str = "tcp" # tcp, udp, http
    transport: str = "tcp" # tcp, udp, http
    direction: str = "egress" # egress, ingress
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
    executor: str = ""
    user: str = ""
    host: str = ""
    working_directory: Optional[str] = None
    parent_process_name: Optional[str] = None


class Host(BaseModel):
    user: str = ""
    hostname: str = ""
    platform: str = "windows" # windows, mac, linux
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
    timestamp: Optional[datetime] = None
    type: str = "" # alert, network, endpoint, process
    activity: List[str] = None #["process_creation"]
    category: List[str] = None #["host", "process"]


class SecurityEvent(BaseModel):
    event:Event = None
    network: Network = None
    source: Source = None
    destination: Destination = None
    host:Host = None
    mitre:List[Mitre] = None


if __name__ == "__main__":
    print(SecurityEvent(event=Event()))    
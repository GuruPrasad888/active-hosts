from fastapi import FastAPI
from pydantic import BaseModel
import json
from threading import Lock
import ipaddress
import time
import subprocess

app = FastAPI()
lock = Lock()

file_storage_path = "/home/guru/ah-files"
interfaces = ["ens37", "ens38"]

class InterfaceInfo(BaseModel):
    subnet: str
    active_devices: list
    disconnected_devices: list

@app.get("/api/interfaces/{interface_name}", response_model=InterfaceInfo)
def get_interface_info(interface_name: str):
    with lock:
        subnet = get_subnet(interface_name)
        print(subnet)
        active_devices = get_devices_from_json(f'{file_storage_path}/Active.json')
        print(active_devices)
        disconnected_devices = get_devices_from_json(f'{file_storage_path}/Disconnected.json')
        print(disconnected_devices)

        return InterfaceInfo(subnet=subnet, active_devices=active_devices, disconnected_devices=disconnected_devices)

def get_subnet(interface_name):
    max_retries = 3
    retries = 0

    while retries < max_retries:
        try:
            result = subprocess.run(["ip", "-j", "-o", "addr", "show", interface_name], capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            if data and data[0]["addr_info"]:
                local_ip = data[0]["addr_info"][0].get("local", "")
                prefix_len = data[0]["addr_info"][0].get("prefixlen", "")
                subnet = f"{local_ip}/{prefix_len}"

                if is_valid_subnet(subnet):
                    return subnet
                else:
                    raise ValueError(f"Retrieved subnet is not in a valid IPv4 address format: {subnet}")
            else:
                raise ValueError("Unable to determine subnet. No valid data found.")
        except subprocess.CalledProcessError as e:
            print(f"Error executing 'ip' command: {e}")
        except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
            print(f"Error parsing JSON output: {e}")

        # Wait for 5 seconds before retrying
        time.sleep(5)
        retries += 1
        print(retries)

    raise ValueError(f"Unable to retrieve a valid subnet after {max_retries} retries.")

def is_valid_subnet(subnet):
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return True
    except ValueError:
        return False

def get_devices_from_json(json_file):
    with lock:
        try:
            with open(json_file, 'r') as file:
                data = json.load(file)
            return data.get('Active Devices', [])  # Assuming 'Active Devices' key contains the list of devices
        except FileNotFoundError:
            # Log the error if needed
            print(f"File not found: {json_file}")
            return []

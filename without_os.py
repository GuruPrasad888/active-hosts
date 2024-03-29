import subprocess
import json
from datetime import datetime
import re


interface = "ens37"
lease_file_path = "/var/lib/misc/dnsmasq.leases"
file_storage_path = "/home/guru/ah-files"


def get_subnet(interface_name):
    try:
        result = subprocess.run(["ip", "-j", "-o", "addr", "show", interface_name], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        local_ip = data[0]["addr_info"][0]["local"]
        prefix_len = data[0]["addr_info"][0]["prefixlen"]
        subnet = f"{local_ip}/{prefix_len}"
        return subnet

    except subprocess.CalledProcessError as e:
        print(f"Error executing 'ip' command: {e}")
        return None
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        print(f"Error parsing JSON output: {e}")
        return None


def get_current_devices(subnet):
    result = subprocess.run(["sudo", "nmap", "-sn", subnet], capture_output=True, text=True)

    lines = result.stdout.strip().split('\n')
    devices = []

    for i in range(len(lines) - 3):
        if "Nmap scan report for" in lines[i]:
            ip_line = lines[i]
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_line)
            if ip_match:
                ip_address = ip_match.group()
                mac_line = lines[i + 2]
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', mac_line)
                if mac_match:
                    mac_address = mac_match.group()
                    device_name = get_device_name_from_lease(ip_address, mac_address)
                    devices.append({
                        'IP Address': ip_address,
                        'MAC Address': mac_address,
                        'Device Name': device_name
                    })
    return devices
    

def get_device_name_from_lease(ip_address, mac_address):
    
    try:
        with open(lease_file_path, 'r') as lease_file:
            leases = lease_file.readlines()

        mac_address = mac_address.lower()  # Convert MAC address to lowercase because mac address in lease file is in lowercase

        for line in leases:
            values = line.strip().split()
            if len(values) >= 4 and values[2] == ip_address and values[1].lower() == mac_address:
                device_name = values[3]
                return device_name

    except FileNotFoundError:
        print(f"DHCP lease file not found: {lease_file_path}")
    except Exception as e:
        print(f"Error reading DHCP lease file: {e}")

    return "Unknown"


def detect_new_devices(previous_devices, current_devices):
    new_devices = [device for device in current_devices if device not in previous_devices]
    removed_devices = [device for device in previous_devices if device not in current_devices]
    return new_devices, removed_devices


def get_connected_time(ip_address, mac_address, active_file):
    with open(active_file, 'r') as file:
        data = json.load(file)

    active_devices = data.get('Active Devices', [])

    for device in active_devices:
        if device.get('IP Address') == ip_address and device.get('MAC Address') == mac_address:
            return device.get('Connected Time', '')

    return ''

def log_device_info_add(device, json_file):
    Time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')

    with open(json_file, 'r') as file:
        data = json.load(file)

    data['Active Devices'].append({
        'Connected Time': Time,
        'IP Address': device.get('IP Address', ''),
        'MAC Address': device.get('MAC Address', ''),
        'Device Name': device.get('Device Name', '')
    })

    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)

def log_device_info_remove(device, json_file):
    Time = datetime.now().strftime('%d-%m-%Y %H:%M:%S') 
    
    connected_time = get_connected_time(device.get('IP Address', ''), device.get('MAC Address', ''), f'{file_storage_path}/Active.json')

    with open(json_file, 'r') as file:
        data = json.load(file)

    data['Disconnected Devices'].append({
        'Connected Time': connected_time,
        'Last Seen': Time,
        'IP Address': device.get('IP Address', ''),
        'MAC Address': device.get('MAC Address', ''),
        'Device Name': device.get('Device Name', '')
    })

    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)

def initialize_json_files():
    for json_file in [f'{file_storage_path}/Active.json', f'{file_storage_path}/Disconnected.json']:
        with open(json_file, 'w') as file:
            json.dump({json_file.split('/')[-1].split('.')[0] + ' Devices': []}, file, indent=2)

def main():
    initialize_json_files()
    subnet = get_subnet(interface)
    previous_devices = []

    try:
        while True:
            current_devices = get_current_devices(subnet)
            new_devices, removed_devices = detect_new_devices(previous_devices, current_devices)

            if new_devices:
                for device in new_devices:               
                    log_device_info_add(device, f'{file_storage_path}/Active.json')     
                    with open(f'{file_storage_path}/Disconnected.json', 'r') as json_file:
                        data = json.load(json_file)
                    data['Disconnected Devices'] = [entry for entry in data['Disconnected Devices'] if
                                                    entry['IP Address'] != device['IP Address'] and
                                                    entry['MAC Address'] != device['MAC Address']]

                    with open(f'{file_storage_path}/Disconnected.json', 'w') as json_file:
                        json.dump(data, json_file, indent=2)

            if removed_devices:
                for device in removed_devices:
                    log_device_info_remove(device, f'{file_storage_path}/Disconnected.json')
                    with open(f'{file_storage_path}/Active.json', 'r') as json_file:
                        data = json.load(json_file)
                    data['Active Devices'] = [entry for entry in data['Active Devices'] if
                                              entry['IP Address'] != device['IP Address'] and
                                              entry['MAC Address'] != device['MAC Address']]
                    with open(f'{file_storage_path}/Active.json', 'w') as json_file:
                        json.dump(data, json_file, indent=2)

            previous_devices = current_devices
   
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
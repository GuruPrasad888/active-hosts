import subprocess
import json
from datetime import datetime
import re
import threading 
import time
import logging
import ipaddress

previous_devices = {}
lock = threading.Lock()

lease_file_path = "/var/lib/misc/dnsmasq.leases"
file_storage_path = "/home/guru/ah-files"
interfaces = ["ens37","ens38"]

logging.basicConfig(filename=f'{file_storage_path}/log_file.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_interface_up(interface_name):
    try:
        result = subprocess.run(['ip', 'a', 'show', interface_name], capture_output=True, text=True)
        return 'state UP' in result.stdout    
    except Exception as e:
        logging.error(f"Error checking interface status: {e}")
        return False

def get_subnet(interface_name):
    try:
        result = subprocess.run(["ip", "-j", "-o", "addr", "show", interface_name], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        if data and data[0]["addr_info"]:
            local_ip = data[0]["addr_info"][0].get("local", "")
            prefix_len = data[0]["addr_info"][0].get("prefixlen", "")
            subnet = f"{local_ip}/{prefix_len}"
            return subnet
        else:
            raise ValueError("Unable to determine subnet. No valid data found.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'ip' command: {e}")
        return None
    except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
        print(f"Error parsing JSON output: {e}")
        return None

def check_subnet_change(interface):
    previous_subnet = get_subnet(interface)
    while is_interface_up(interface):
        time.sleep(3)  # Check every 3 seconds (adjust as needed)
        current_subnet = get_subnet(interface)
        print(current_subnet)
        if current_subnet != previous_subnet:
            print(time.time())
            print(f"Subnet change detected for {interface}. Clearing entries.")
            clear_entries_in_active_json(previous_subnet)
            previous_subnet = current_subnet  # Update previous_subnet with the current subnet

def clear_entries_in_active_json(subnet_to_clear):
    with lock:
        with open(f'{file_storage_path}/Active.json', 'r') as json_file:
            data = json.load(json_file)

        # Remove entries with IP addresses in the previous subnet
        data['Active Devices'] = [entry for entry in data['Active Devices'] if not is_ip_in_subnet(entry['IP Address'], subnet_to_clear)]

        with open(f'{file_storage_path}/Active.json', 'w') as json_file:
            json.dump(data, json_file, indent=2)

def is_ip_in_subnet(ip_address, subnet):
    try:
        ip_network = ipaddress.IPv4Network(subnet, strict=False)
        return ipaddress.IPv4Address(ip_address) in ip_network
    except ValueError:
        return False

def get_current_devices(subnet):
    if subnet is None:
        # Handle the case where subnet is None
        return []

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

    log_message = f"{device.get('IP Address', '')}, {device.get('MAC Address', '')}, {device.get('Device Name', '')}, added"
    logging.info(log_message)

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

    log_message = f"{device.get('IP Address', '')}, {device.get('MAC Address', '')}, {device.get('Device Name', '')}, removed"
    logging.info(log_message)

def initialize_json_files():
    for json_file in [f'{file_storage_path}/Active.json', f'{file_storage_path}/Disconnected.json']:
        with open(json_file, 'w') as file:
            json.dump({json_file.split('/')[-1].split('.')[0] + ' Devices': []}, file, indent=2)

def process_interface(interface):
    try:
        # Start the subnet change detection thread
        subnet_thread = threading.Thread(target=check_subnet_change, args=(interface,))
        subnet_thread.start()

        while is_interface_up(interface):
            subnet = get_subnet(interface)
            current_devices = get_current_devices(subnet)
            new_devices, removed_devices = detect_new_devices(previous_devices.get(interface, []), current_devices)

            with lock:
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

                previous_devices[interface] = current_devices

            time.sleep(5)  # Check every 5 seconds for new devices

    except KeyboardInterrupt:
        pass

def main():
    initialize_json_files()
    up_interfaces = []
    down_interfaces = []
    while True:
        for interface in interfaces:
            if is_interface_up(interface):
                if interface not in up_interfaces:
                    # If the interface is up and not in previous_devices, start a new thread
                    thread = threading.Thread(target=process_interface, args=(interface,))
                    thread.start()
                    previous_devices[interface] = []

        time.sleep(3)  # Adjust the sleep duration as needed for checking intervals

if __name__ == "__main__":
    main()
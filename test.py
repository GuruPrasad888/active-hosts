import subprocess
import json
from datetime import datetime
import re
import threading 
import time
import logging
import ipaddress
import psutil
import os

previous_devices = {}
lock = threading.Lock()
should_run = {}  # Flag to signal threads to stop

lease_file_path = "/var/lib/misc/dnsmasq.leases"
json_file_path = "/home/guru/ah-files"
log_file_path = "/home/guru/log-files"
interfaces = ["ens37","ens38"]

logging.basicConfig(filename=f'{log_file_path}/log_file.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def stop_thread(interface):
    should_run[interface] = False
    logging.info(f"Stopping thread for interface: {interface}")

def is_interface_up(interface_name):
    try:
        stats = psutil.net_if_stats()
        if interface_name in stats:
            interface_info = stats[interface_name]
            if interface_info.isup:
                return True

    except Exception:
        return False
    return False

def is_valid_subnet(subnet):
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return True
    except ValueError:
        return False

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

def check_subnet_change(interface):
    previous_subnet = get_subnet(interface)
    while is_interface_up(interface):
        time.sleep(3)  # Check every 3 seconds
        current_subnet = get_subnet(interface)
        if current_subnet != previous_subnet:
            print(f"Subnet change detected for {interface}. Clearing entries.")
            clear_entries_in_active_json(previous_subnet)
            previous_subnet = current_subnet

def clear_entries_in_active_json(subnet_to_clear):
    with lock:
        with open(f'{json_file_path}/Active.json', 'r') as json_file:
            data = json.load(json_file)

        # Remove entries with IP addresses in the previous subnet
        data['Active Devices'] = [entry for entry in data['Active Devices'] if not is_ip_in_subnet(entry['IP Address'], subnet_to_clear)]

        with open(f'{json_file_path}/Active.json', 'w') as json_file:
            json.dump(data, json_file, indent=2)

def is_ip_in_subnet(ip_address, subnet):
    try:
        ip_network = ipaddress.IPv4Network(subnet, strict=False)
        return ipaddress.IPv4Address(ip_address) in ip_network
    except ValueError:
        return False

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
                if device_name == "*":
                    return "Unknown"
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


def log_device_info_add(device, json_file, interface):
    Time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')

    with open(json_file, 'r') as file:
        data = json.load(file)

    interface_data = data.get(interface, {})
    devices = interface_data.get('devices', [])

    # Update existing entry or add a new one
    existing_entry = next((entry for entry in devices if entry['IP Address'] == device['IP Address'] and entry['MAC Address'] == device['MAC Address']), None)
    if existing_entry:
        existing_entry.update({
            'MAC Address': existing_entry.get('MAC Address', ''),
            'IP Address': device.get('IP Address', ''),
            'Connected Time': Time,
            'Device Name': device.get('Device Name', '')
        })
    else:
        # Add a new entry
        devices.append({
            'MAC Address': device.get('MAC Address', ''),
            'IP Address': device.get('IP Address', ''),
            'Connected Time': Time,
            'Device Name': device.get('Device Name', '')
        })

    interface_data['devices'] = devices
    data[interface] = interface_data

    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)

    logging.info(f"{device.get('IP Address', '')}, {device.get('MAC Address', '')}, {device.get('Device Name', '')}, added to {interface}")

def log_device_info_remove(device, json_file, interface):
    Time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')

    with open(json_file, 'r') as file:
        data = json.load(file)

    interface_data = data.get(interface, {})
    devices = interface_data.get('devices', [])

    devices.append({
        'MAC Address': device.get('MAC Address', ''),
        'IP Address': device.get('IP Address', ''),
        'Last Seen': Time,
        'Device Name': device.get('Device Name', '')
    })

    interface_data['devices'] = devices
    data[interface] = interface_data

    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)

    logging.info(f"{device.get('IP Address', '')}, {device.get('MAC Address', '')}, {device.get('Device Name', '')}, removed from {interface}")


def initialize_json_files():

    # Initialize Active.json in write mode
    active_json_file = os.path.join(json_file_path, "Active.json")
    with open(active_json_file, 'w') as active_file:
        active_file.write("{}")

    # Initialize Disconnected.json in append mode (create if not exists)
    disconnected_json_file = os.path.join(json_file_path, "Disconnected.json")
    with open(disconnected_json_file, 'a+') as disconnected_file:
        disconnected_file.seek(0)  # Move the cursor to the beginning to check if the file is empty
        if not disconnected_file.read(1):
            # If the file is empty, write an empty dictionary to initialize it
            disconnected_file.write("{}")

def copy_active_file_data():

    active_json_file = os.path.join(json_file_path, 'Active.json')
    disconnected_json_file = os.path.join(json_file_path, 'Disconnected.json')
    previous_active_json_file = os.path.join(json_file_path, 'PreviousActiveDevices.json')
    previous_disconnected_json_file = os.path.join(json_file_path, 'PreviousDisconnectedDevices.json')

    if os.path.exists(active_json_file):
        # Read the contents of active.json
        with open(active_json_file, 'r') as active_file:
            active_data = json.load(active_file)

        # Create or clear previous_devices.json
        if os.path.exists(previous_active_json_file):
            with open(previous_active_json_file, 'w') as previous_devices_file:
                previous_devices_file.write("{}")
        else:
            with open(previous_active_json_file, 'x') as previous_devices_file:
                previous_devices_file.write("{}")

        # Write contents to previous_devices.json
        with open(previous_active_json_file, 'w') as previous_devices_file:
            json.dump(active_data, previous_devices_file, indent=2)

        # Clear contents in active.json
        with open(active_json_file, 'w') as active_file:
            active_file.write("{}")

    else:
        # active.json doesn't exist, create previous devices file 
        if os.path.exists(previous_active_json_file):
            with open(previous_active_json_file, 'w') as previous_devices_file:
                previous_devices_file.write("{}")
        else:
            with open(previous_active_json_file, 'x') as previous_devices_file:
                previous_devices_file.write("{}")

    if os.path.exists(disconnected_json_file):
        # Read the contents of disconnected.json
        with open(disconnected_json_file, 'r') as disconnected_file:
            disconnected_data = json.load(disconnected_file)

        # Create or clear previous_disconnected_devices.json
        if os.path.exists(previous_disconnected_json_file):
            with open(previous_disconnected_json_file, 'w') as previous_devices_file:
                previous_devices_file.write("{}")
        else:
            with open(previous_disconnected_json_file, 'x') as previous_devices_file:
                previous_devices_file.write("{}")

        # Write contents to previous_disconnected_devices.json
        with open(previous_disconnected_json_file, 'w') as previous_devices_file:
            json.dump(disconnected_data, previous_devices_file, indent=2)

        # Clear contents in disconnected .json
        with open(disconnected_json_file, 'w') as disconnected_file:
            disconnected_file.write("{}")

    else:
        # disconnected.json doesn't exist, create previous devices file 
        if os.path.exists(previous_disconnected_json_file):
            with open(previous_disconnected_json_file, 'w') as previous_devices_file:
                previous_devices_file.write("{}")
        else:
            with open(previous_disconnected_json_file, 'x') as previous_devices_file:
                previous_devices_file.write("{}")

def process_interface(interface):
    try:
        should_run[interface] = True
        subnet_thread = threading.Thread(target=check_subnet_change, args=(interface,))
        subnet_thread.start()

        while should_run.get(interface, True) and is_interface_up(interface):
            subnet = get_subnet(interface)
            current_devices = get_current_devices(subnet)
            new_devices, removed_devices = detect_new_devices(previous_devices.get(interface, []), current_devices)

            with lock:
                if new_devices:
                    for device in new_devices:
                        log_device_info_add(device, f'{json_file_path}/Active.json', interface)
                        interface_json_file = f'{json_file_path}/Disconnected.json'
                        with open(interface_json_file, 'r') as json_file:
                            data = json.load(json_file)
                            data[interface] = data.get(interface, {'devices': []})
                            data[interface]['devices'] = [entry for entry in data[interface]['devices'] if
                                                           'IP Address' in entry and entry['IP Address'] != device['IP Address'] and
                                                           'MAC Address' in entry and entry['MAC Address'] != device['MAC Address']]

                        with open(interface_json_file, 'w') as json_file:
                            json.dump(data, json_file, indent=2)

                if removed_devices:
                    for device in removed_devices:
                        log_device_info_remove(device, f'{json_file_path}/Disconnected.json', interface)
                        interface_json_file = f'{json_file_path}/Active.json'
                        with open(interface_json_file, 'r') as json_file:
                            data = json.load(json_file)
                            data[interface] = data.get(interface, {'devices': []})
                            data[interface]['devices'] = [entry for entry in data[interface]['devices'] if
                                                           'IP Address' in entry and entry['IP Address'] != device['IP Address'] and
                                                           'MAC Address' in entry and entry['MAC Address'] != device['MAC Address']]
                        with open(interface_json_file, 'w') as json_file:
                            json.dump(data, json_file, indent=2)

                previous_devices[interface] = current_devices

            time.sleep(5)  # Check every 5 seconds for new devices

    except KeyboardInterrupt:
        pass

def main():
    copy_active_file_data()
    initialize_json_files()
    up_interfaces = []
    down_interfaces = []

    # Initialize should_run flags for each interface
    for interface in interfaces:
        should_run[interface] = True

    while True:
        for interface in interfaces:
            if is_interface_up(interface):
                if interface not in up_interfaces:
                    up_interfaces.append(interface)
                    thread = threading.Thread(target=process_interface, args=(interface,))
                    thread.start()
                    previous_devices[interface] = []

                    if interface in down_interfaces:
                        down_interfaces.remove(interface)
            else:
                if interface not in down_interfaces:
                    down_interfaces.append(interface)
                    if interface in up_interfaces:
                        up_interfaces.remove(interface)
                        stop_thread(interface)  # Signal the thread to stop
#            active_threads = threading.enumerate()
#            print(f"Active threads: {len(active_threads)} - Thread names: {', '.join([t.name for t in active_threads])}")

        time.sleep(3)  # Adjust the sleep duration as needed for checking intervals

if __name__ == "__main__":
    main()
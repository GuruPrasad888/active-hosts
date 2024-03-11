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

class ActiveHosts:
    def __init__(self):
        self.configuration_file_path = "/home/chiefnet/ChiefNet/ConfigurationFiles/SystemConfiguration.json"
        self.lease_file_path = "/var/lib/misc/dnsmasq.leases"
        self.json_file_path = "/home/chiefnet/active-hosts"
        self.log_file_path = "/home/chiefnet/active-hosts"

        self.previous_devices = {}
        self.lock = threading.Lock()
        self.should_run = {}  # Flag to signal threads to stop

        logging.basicConfig(filename=f'{self.log_file_path}/log_file.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def get_lan_interfaces(self, file_path):
        lan_interfaces = []
        if not os.path.isfile(file_path):
            return lan_interfaces

        try:
            with open(file_path, 'r') as json_file:
                data = json.load(json_file)

                # Extract LAN interfaces
                if "system_information" in data and "lan_interfaces" in data["system_information"]:
                    lan_interfaces = data["system_information"]["lan_interfaces"]
                else:
                    print("LAN interfaces not found in the JSON file.")
                    return lan_interfaces

        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return lan_interfaces
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return lan_interfaces

        return lan_interfaces

    def stop_thread(self, interface):
        self.should_run[interface] = False
        logging.info(f"Stopping thread for interface: {interface}")

    def is_interface_up(self, interface_name):
        try:
            stats = psutil.net_if_stats()
            if interface_name in stats:
                interface_info = stats[interface_name]
                if interface_info.isup:
                    return True

        except Exception:
            return False
        return False

    def is_valid_subnet(self, subnet):
        try:
            ipaddress.IPv4Network(subnet, strict=False)
            return True
        except ValueError:
            return False

    def get_subnet(self, interface_name):
        try:
            result = subprocess.run(["ip", "-j", "-o", "addr", "show", interface_name], capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            if data and data[0]["addr_info"]:
                local_ip = data[0]["addr_info"][0].get("local", "")
                prefix_len = data[0]["addr_info"][0].get("prefixlen", "")
                subnet = f"{local_ip}/{prefix_len}"

                if self.is_valid_subnet(subnet):
                    return subnet
                else:
                    return None
                    raise ValueError(f"Retrieved subnet is not in a valid IPv4 address format: {subnet}")
            else:
                return None
                raise ValueError("Unable to determine subnet. No valid data found.")
        except subprocess.CalledProcessError as e:
            return None
            print(f"Error executing 'ip' command: {e}")
        except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
            return None
            print(f"Error parsing JSON output: {e}")

    def check_subnet_change(self, interface):
        previous_subnet = self.get_subnet(interface)
        if previous_subnet != None:
            while self.is_interface_up(interface):
                time.sleep(3)  # Check every 3 seconds
                current_subnet = self.get_subnet(interface)
                if current_subnet != None and current_subnet != previous_subnet:
                    print(f"Subnet change detected for {interface}. Clearing entries.")
                    self.clear_entries_in_active_json(interface)
                    previous_subnet = current_subnet
                else:
                    pass
        else:
            pass

    def clear_entries_in_active_json(self, interface):
        with self.lock:
            try:
                with open(f'{self.json_file_path}/Active.json', "r") as active_file:
                    active_data = json.load(active_file)
            except FileNotFoundError:
                # If the file doesn't exist, initialize it with an empty dictionary
                active_data = {}

            # Update the interface state in the JSON data (without modifying devices)
            if interface in active_data:
                active_data[interface]["devices"] = []

            # Save the updated data back to the JSON file
            with open(f'{self.json_file_path}/Active.json', "w") as active_file:
                json.dump(active_data, active_file, indent=2)

    def get_current_devices(self, subnet):
        try:
            result = subprocess.run(["sudo", "nmap", "-sn", subnet], check=True, capture_output=True, text=True)

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
                            device_name = self.get_device_name_from_lease(ip_address, mac_address)
                            devices.append({
                                'IP Address': ip_address,
                                'MAC Address': mac_address,
                                'Device Name': device_name
                            })
            return devices
        except subprocess.CalledProcessError as e:
            print(f"Error executing nmap command: {e}")

    def get_device_name_from_lease(self, ip_address, mac_address):
        try:
            with open(self.lease_file_path, 'r') as lease_file:
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
            print(f"DHCP lease file not found: {self.lease_file_path}")
        except Exception as e:
            print(f"Error reading DHCP lease file: {e}")

        return "Unknown"

    def detect_new_devices(self, previous_devices, current_devices):
        new_devices = [device for device in current_devices if device not in previous_devices]
        removed_devices = [device for device in previous_devices if device not in current_devices]
        return new_devices, removed_devices

    def log_device_info_add(self, device, json_file, interface):
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

    def log_device_info_remove(self, device, json_file, interface):
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

    def initialize_json_files(self):

        # Initialize Active.json in write mode
        active_json_file = os.path.join(self.json_file_path, "Active.json")
        with open(active_json_file, 'w') as active_file:
            active_file.write("{}")

        # Initialize Disconnected.json in append mode (create if not exists)
        disconnected_json_file = os.path.join(self.json_file_path, "Disconnected.json")
        with open(disconnected_json_file, 'w') as disconnected_file:
            disconnected_file.write("{}")


    def update_interface_state(self, interface, interface_state):
        # Check if the interface is down
        if interface_state == "down":
            try:
                with open(f'{self.json_file_path}/Active.json', "r") as active_file:
                    active_data = json.load(active_file)
            except FileNotFoundError:
                # If the file doesn't exist, initialize it with an empty dictionary
                active_data = {}
            # Clear the devices list in the specified interface
            if interface in active_data:
                cleared_devices = active_data[interface].get("devices", [])
                active_data[interface]["interface_state"] = interface_state
                active_data[interface]["devices"] = []

                # Save the updated data back to the Active.json file
                with open(f'{self.json_file_path}/Active.json', "w") as active_file:
                    json.dump(active_data, active_file, indent=2)

                # Load the existing JSON data from Disconnected.json
                try:
                    with open(f'{self.json_file_path}/Disconnected.json', "r") as disconnected_file:
                        existing_disconnected_data = json.load(disconnected_file)
                except FileNotFoundError:
                    # If the file doesn't exist, initialize it with an empty dictionary
                    existing_disconnected_data = {}

                # Append the cleared data to the existing data in the corresponding interface of Disconnected.json
                existing_disconnected_data[interface] = existing_disconnected_data.get(interface, {})
                existing_disconnected_data[interface]["devices"] = existing_disconnected_data[interface].get("devices", []) + cleared_devices

                # Save the updated data back to the Disconnected.json file
                with open(f'{self.json_file_path}/Disconnected.json', "w") as disconnected_file:
                    json.dump(existing_disconnected_data, disconnected_file, indent=2)
            else:
                active_data[interface]["interface_state"] = interface_state
                active_data[interface]["devices"] = []
                with open(f'{self.json_file_path}/Active.json', "w") as active_file:
                    json.dump(active_data, active_file, indent=2)

        elif interface_state == "up":
            try:
                with open(f'{self.json_file_path}/Active.json', "r") as active_file:
                    active_data = json.load(active_file)
            except FileNotFoundError:
                # If the file doesn't exist, initialize it with an empty dictionary
                active_data = {}

            # Update the interface state in the JSON data (without modifying devices)
            if interface in active_data:
                active_data[interface]["interface_state"] = interface_state
            else:
                active_data[interface] = {"interface_state": interface_state, "devices": []}

            # Save the updated data back to the JSON file
            with open(f'{self.json_file_path}/Active.json', "w") as active_file:
                json.dump(active_data, active_file, indent=2)


    def copy_active_file_data(self):

        active_json_file = os.path.join(self.json_file_path, 'Active.json')
        disconnected_json_file = os.path.join(self.json_file_path, 'Disconnected.json')
        previous_active_json_file = os.path.join(self.json_file_path, 'PreviousActiveDevices.json')
        previous_disconnected_json_file = os.path.join(self.json_file_path, 'PreviousDisconnectedDevices.json')

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

    def process_interface(self, interface):
        try:
            self.should_run[interface] = True
            subnet_thread = threading.Thread(target=self.check_subnet_change, args=(interface,))
            subnet_thread.start()

            while self.should_run.get(interface, True):
                subnet = self.get_subnet(interface)
                if subnet != None:
                    current_devices = self.get_current_devices(subnet)
                    new_devices, removed_devices = self.detect_new_devices(self.previous_devices.get(interface, []), current_devices)

                    with self.lock:
                        if new_devices:
                            for device in new_devices:
                                self.log_device_info_add(device, f'{self.json_file_path}/Active.json', interface)
                                # Remove entries in Disconnected.json file
                                interface_json_file = f'{self.json_file_path}/Disconnected.json'
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
                                self.log_device_info_remove(device, f'{self.json_file_path}/Disconnected.json', interface)
                                # Remove entries in Active.json file
                                interface_json_file = f'{self.json_file_path}/Active.json'
                                with open(interface_json_file, 'r') as json_file:
                                    data = json.load(json_file)
                                    data[interface] = data.get(interface, {'devices': []})
                                    data[interface]['devices'] = [entry for entry in data[interface]['devices'] if
                                                                'IP Address' in entry and entry['IP Address'] != device['IP Address'] and
                                                                'MAC Address' in entry and entry['MAC Address'] != device['MAC Address']]
                                with open(interface_json_file, 'w') as json_file:
                                    json.dump(data, json_file, indent=2)

                        self.previous_devices[interface] = current_devices

                    time.sleep(5)  # Check every 5 seconds for new devices
                else:
                    pass
        except KeyboardInterrupt:
            pass

    def main(self):
        self.copy_active_file_data()
        self.initialize_json_files()
        lan_interfaces = self.get_lan_interfaces(self.configuration_file_path)
        up_interfaces = []
        down_interfaces = []

        # Initialize should_run flags for each interface
        for interface in lan_interfaces:
            self.should_run[interface] = True

        while True:
            for interface in lan_interfaces:
                if self.is_interface_up(interface):
                    if interface not in up_interfaces:
                        up_interfaces.append(interface)
                        thread = threading.Thread(target=self.process_interface, args=(interface,))
                        thread.start()
                        self.previous_devices[interface] = []

                        if interface in down_interfaces:
                            down_interfaces.remove(interface)
                        interface_state = "up"
                        self.update_interface_state(interface, interface_state)
                else:
                    if interface not in down_interfaces:
                        down_interfaces.append(interface)
                        if interface in up_interfaces:
                            up_interfaces.remove(interface)
                            self.stop_thread(interface)  # Signal the thread to stop
                        interface_state = "down"
                        self.update_interface_state(interface, interface_state)

            time.sleep(3)  # Adjust the sleep duration as needed for checking intervals

if __name__ == "__main__":
    monitor = ActiveHosts()
    monitor.main()

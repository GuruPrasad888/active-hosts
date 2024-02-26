import subprocess
import json
from datetime import datetime
import re
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sniff
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp
from pyp0f.net.layers.tcp import TCPFlag
from pyp0f.net.scapy import ScapyPacket
import threading


interface = "ens37"
lease_file_path = "/var/lib/misc/dnsmasq.leases"
output_file = "output.txt"
file_storage_path = "/home/guru/ah-files"


DATABASE.load()

exit_flag = threading.Event()

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
            if len(values) >= 4 and values[2] == ip_address and values[1].lower() == mac_address:   # Check if IP address and MAC address match
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
    ip_address = device['IP Address']
    os_info = get_os_from_output_file(ip_address, output_file)

    with open(json_file, 'r') as file:
        data = json.load(file)
    data['Active Devices'].append({
        'Time': Time,
        'IP Address': device['IP Address'],
        'MAC Address': device['MAC Address'],
        'Device Name': device['Device Name'],
        'OS': os_info
    })
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)


def log_device_info_remove(device, json_file):
    Time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    ip_address = device['IP Address']
    os_info = get_os_from_output_file(ip_address, output_file)
    connected_time = get_connected_time(device.get('IP Address', ''), device.get('MAC Address', ''), f'{file_storage_path}/Active.json')

    
    with open(json_file, 'r') as file:
        data = json.load(file)
    data['Disconnected Devices'].append({
        'Connected Time': connected_time,
        'Last Seen': Time,
        'IP Address': device['IP Address'],
        'MAC Address': device['MAC Address'],
        'Device Name': device['Device Name'],
        'OS': os_info
    })
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=2)
    remove_ip_address_and_os(ip_address, output_file)


def initialize_json_files():
    for json_file in [f'{file_storage_path}/Active.json', f'{file_storage_path}/Disconnected.json']:
        with open(json_file, 'w') as file:
            json.dump({json_file.split('.')[0] + ' Devices': []}, file, indent=2)  # Initializing JSON file


def update_unknown_os(active_json, output_file):
    try:
        # Load the content of Active.json
        with open(f'{file_storage_path}/Active.json', 'r') as file:
            data = json.load(file)

        # Iterate through the 'Active Devices'
        for device in data['Active Devices']:
            if device['OS'] == 'Unknown':
                # Call get_os_from_output_file function and update 'OS' field
                ip_address = device['IP Address']
                new_os = get_os_from_output_file(ip_address, output_file)
                device['OS'] = new_os

        # Write the updated data back to Active.json
        with open(f'{file_storage_path}/Active.json', 'w') as file:
            json.dump(data, file, indent=2)

    except FileNotFoundError:
        print(f"Error: {f'{file_storage_path}/Active.json'} not found")
    except Exception as e:
        print(f"Error: {e}")


def initialize_empty_text_file(file_name):
    try:
        with open(file_name, 'w'):
            pass  # Open the file in write mode, creating it if it doesn't exist
    except Exception as e:
        print(f"Error: {e}")


def is_ip_in_file(ip_address, file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if ip_address in line:
                    return True
        return False
    except FileNotFoundError:
        return False


def get_os_from_output_file(ip_address, output_file):
    try:
        with open(output_file, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if ip_address in line:
                    # Extract the OS information from the line
                    os_info = line.split(':')[-1].strip()
                    return os_info
    except FileNotFoundError:
        return 'Unknown'

    return 'Unknown'  # If IP address not found in output file or file not found
    
    
def remove_ip_address_and_os(ip_address, output_file):
    try:
        # Read the contents of the output_file
        with open(output_file, 'r') as file:
            lines = file.readlines()

        # Filter out the line with the specified IP address
        updated_lines = [line for line in lines if ip_address not in line]

        # Write the updated lines back to the output_file
        with open(output_file, 'w') as file:
            file.writelines(updated_lines)

    except FileNotFoundError:
        print(f"Error: {f'{file_storage_path}/{output_file}'} not found")
    except Exception as e:
        print(f"Error: {e}")


def handle_packet(packet: ScapyPacket) -> None:
    if IP in packet:
        ip_layer = IP
    elif IPv6 in packet:
        ip_layer = IPv6
    else:
        return  # Skip non-IPv4 and non-IPv6 packets
    
    ip_address = packet[ip_layer].src

    if not is_ip_in_file(ip_address, f'{file_storage_path}/{output_file}'):  # Check if the IP address is already in the file

        tcp_layer = packet.getlayer(TCP)

        if tcp_layer:
            flags = TCPFlag(int(tcp_layer.flags))

            # SYN/SYN+ACK packet, fingerprint
            if flags in (TCPFlag.SYN, TCPFlag.SYN | TCPFlag.ACK):
                tcp_result = fingerprint_tcp(packet)

                # Check if the TCPResult object has a match attribute and a record attribute
                if hasattr(tcp_result, 'match') and hasattr(tcp_result.match, 'record'):
                    
                    os_info = tcp_result.match.record.label.name
                                        
                    with open(f'{file_storage_path}/{output_file}', 'a') as text_file:       # Append the data to the text file
                        text_file.write(f"{ip_address} : {os_info}\n")
    else:
        return

def main():
    global exit_flag
    initialize_empty_text_file(output_file)
    initialize_json_files()
    subnet = get_subnet(interface)
    previous_devices = []

    try:
        while not exit_flag.is_set():
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
            update_unknown_os(f'{file_storage_path}/Active.json', f'{file_storage_path}/{output_file}')
   
    except Exception as e:
        print(f"Error in main thread: {e}")
    finally:
        exit_flag.set()  # Set the exit flag to terminate the sniffing thread


def sniff_packets():
    global exit_flag
    try:
        # Sniff all TCP packets on the ens37 interface
        sniff(iface=interface, filter="tcp", prn=handle_packet)
    except Exception as e:
        print(f"Error in sniff_packets: {e}")
    finally:
        exit_flag.set()  # Set the exit flag to terminate the main thread


if __name__ == "__main__":
    # Start the main function in the main thread
    t1 = threading.Thread(target=main)
    t1.start()

    # Start the sniffing function in another thread
    t2 = threading.Thread(target=sniff_packets)
    t2.start()

    try:
        # Join threads to wait for their completion
        t1.join()
        t2.join()

    except KeyboardInterrupt:
        print("\nTerminated")

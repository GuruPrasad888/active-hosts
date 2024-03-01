import subprocess
import json
import time
import ipaddress

def is_valid_subnet(subnet):
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
                print(f"Retrieved subnet is not in a valid IP address format: {subnet}")
        else:
            raise ValueError("Unable to determine subnet. No valid data found.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'ip' command: {e}")
    except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
        print(f"Error parsing JSON output: {e}")
  
  
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return True
    except ValueError:
        return False

def get_subnet(interface_name):
    max_retries = 3
    retries = 0

    while retries < max_retries:


        # Wait for 5 seconds before retrying
        time.sleep(5)
        retries += 1
        print(retries)

    raise ValueError(f"Unable to retrieve a valid subnet after {max_retries} retries.")

# Install Nmap: https://nmap.org/download.html
# Alternative if the main goal is port scanning speed: https://github.com/robertdavidgraham/masscan
# pip install python-nmap
# pip install psutil
# pip install ping3
# pip install scapy
# pip install mac-vendor-lookup

import re
import ipaddress
import psutil
import socket
import nmap
from ping3 import ping, verbose_ping
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import pandas as pd

## Check avaiable network interfaces with psutil
network_interfaces = psutil.net_if_addrs()

# Print information about each network interface
for interface, addresses in network_interfaces.items():
    print(f"Interface: {interface}")
    for address in addresses:
        if address.family == socket.AF_INET:
            print(f"  IPv4 Address: {address.address}")
            print(f"  Netmask: {address.netmask}")
        elif address.family == socket.AddressFamily.AF_INET6:
            print(f"  IPv6 Address: {address.address}")
        elif address.family == psutil.AF_LINK:
            print(f"  MAC Address: {address.address}")
    print()

# Define the target IP address or IP range to scan manually if you want (in this case comment out the following secion)
# start_ip = '192.168.1.1'
# end_ip = '192.168.1.25'
# ip_range = '192.168.1.1/24'
# ip_target = '192.168.1.1-25'

# Want to check if the entered IP address has the correct format
def get_ipv4_start():
    while True:
        user_input = input("Enter the start of the IPv4 address range: ")
        try:
            ipaddress.IPv4Address(user_input)
            return user_input
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address format. Please try again.")

def get_ipv4_stop():
    while True:
        user_input = input("Enter the end of the IPv4 address range ")
        try:
            ipaddress.IPv4Address(user_input)
            return user_input
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address format. Please try again.")

# Want to check if the entered netmask has the correct format

def valid_netmask(user_input):
    pattern = r'^/[1-9][0-9]$'
    return bool(re.match(pattern, user_input))

# Function to get valid input
def get_netmask():
    while True:
        user_input = input("Enter input in the form of '/DD': ")
        if valid_netmask(user_input):
            return user_input
        else:
            print("Invalid input format. Please enter in the form of '/DD'.")

# User input for the IP range
start_ip = get_ipv4_start()
end_ip = get_ipv4_stop()
netmask_range = get_netmask()
ip_range = start_ip + netmask_range
ip_target = start_ip + '-' + end_ip.split('.')[-1]

## Createing a dataframe to store all the collected data
ip_df = pd.DataFrame(columns=['IP', 'ICMP response time (ms)', 'ARP', 'Vendor', 'Spec ports', 'TCP', 'UDP'])

for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
    ip = f"{start_ip.rsplit('.', 1)[0]}.{i}"
    ip_df.loc[len(ip_df)] = [ip, None, None, None, None, None, None]

### ICMP ping each IP address with ping3
def icmp():
    for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        ip = f"{start_ip.rsplit('.', 1)[0]}.{i}"
        response_time = ping(ip)
        if isinstance(response_time, float):
            print(f'{ip} is responding to ping: {response_time} ms')
            ip_df.loc[ip_df['IP'] == ip, 'ICMP response time (ms)'] = response_time

# Update the vendor list
MacLookup().update_vendors

### Vendor lookup
def get_vendor(mac_address):
    mac_lookup = MacLookup()
    try:
        vendor = mac_lookup.lookup(mac_address)
        return vendor
    except Exception as e:
        return None
    
### ARP check on the subnet with Scapy
def arp():
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)

    # Create an Ethernet frame
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')

    packet = ether/arp
    arp_result = srp(packet, timeout=3, verbose=0)[0]    

    # Iterate through responses and print live hosts
    for sent, received in arp_result:
        print(f'IP Address: {received.psrc} on {received.hwsrc} is alive')
        ip_df.loc[ip_df['IP'] == received.psrc, 'ARP'] = received.hwsrc
        ip_df.loc[ip_df['IP'] == received.psrc, 'Vendor'] = get_vendor(received.hwsrc)


### Socket Port Scanning
def port_spec(*args):
    # Simple port scanning for the specified ports only with socket
    # Ports to scan for the socket scanning method, edit as needed
    # ports_to_scan = [80, 443, 22] taking it from user input for now
    for ip in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        host = f"{start_ip.rsplit('.', 1)[0]}.{ip}"
        ports_to_scan = list(map(int, args[0]))
        ports = []
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Adjust the timeout as needed
            result = sock.connect_ex((host, port))
            # Define a custom function to append values to a list
            if result == 0:
                print(f'{host}:{port} is alive')
                ports.append(port)
                ip_df.loc[ip_df['IP'] == host, 'Spec ports'] = [ports]
            sock.close()

### Nmap Port Scanning
def port():
    # Initialize the Nmap PortScanner object
    nm = nmap.PortScanner()

    # Perform the TCP scan with Nmap
    nm.scan(hosts=ip_target, arguments='-p 1-1024')
    # Iterate through scan results  
    for host in nm.all_hosts():
        print(f"Host: {host}")
        ports = []
        # Check if the "tcp" key exists in the host's data
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                ports.append(port)
                ip_df.loc[ip_df['IP'] == host, 'TCP'] = [ports]
                print(f"Port {port}: {nm[host]['tcp'][port]['state']}")
        else:
            print('No open TCP ports found.')

    # Perform the UDP scan with Nmap
    nm.scan(hosts=ip_target, arguments='-p U:1-1024')
    # Iterate through scan results
    for host in nm.all_hosts():
        print(f"Host: {host}")
        ports = []
        # Check if the "udp" key exists in the host's data
        if 'udp' in nm[host]:
            for port in nm[host]['udp']:
                ports.append(port)
                ip_df.loc[ip_df['IP'] == host, 'UDP'] = [ports]
                print(f"UDP Port {port}: {nm[host]['udp'][port]['state']}")
        else:
            print('No open UDP ports found.')

# Get user input on what we wanna look for
def main():
    print('What do you want to scan for? \n1: ICMP \n2: ARP \n3: Specific TCP port scan \n4: Scanning all TCP and UDP the ports')

    choices = input('Enter the numbers of your choices separated by spaces: ').split()

    for choice in choices:
        if choice == '1':
            icmp()
        elif choice == '2':
            arp()
        elif choice == '3':
            ports_to_scan = input('Enter the ports to scan separated by a comma: ').split(',')
            port_spec(ports_to_scan)
        elif choice == '4':
            port()
        else:
            print(f"Invalid choice '{choice}'. Ignoring.")

if __name__ == '__main__':
    main()
    ip_df.to_csv('IP_scan_output.csv', index=False)
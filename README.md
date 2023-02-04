
# Automated Network Scanner

This script allows you to automate the process of scanning a network to identify active hosts and gather information about them.

## Requirements
- Python 3 installed on your computer
- Scapy library installed (run `pip install scapy` to install it)

## How the script works
The script sends an Internet Control Message Protocol (ICMP) Echo Request (ping) to each IP address in a specified range, and records the IP addresses of the hosts that respond. It then uses the Simple Network Management Protocol (SNMP) to retrieve information about each active host, such as its hostname, uptime, and system name.

## How to use the script
1. Open a text editor and copy the code from the code section of this documentation into a new file. Save the file with a `.py` extension, for example `network_scan.py`.
2. Open the terminal or command prompt on your computer.
3. Navigate to the directory where you saved the script file.
4. Edit the code to specify the IP address range you want to scan.
5. Run the script by typing `python network_scan.py` in the terminal or command prompt and pressing enter.
6. The script will send pings to each IP address in the specified range, and retrieve information about the active hosts using SNMP.
7. After the script has run, you will see the results of the network scan printed on the screen, including the IP addresses, hostnames, uptimes, and system names of the active hosts.

```python
from scapy.layers.l2 import arping
from pysnmp.hlapi import *

# Specify the IP address range to scan
network = "192.168.1.0/24"

# Send an ARP ping to each IP address in the specified range
results = arping(network)

# Create a list to store the information about the active hosts
active_hosts = []

# Retrieve information about each active host using SNMP
for host in results[0]:
    ip_address = host[1].psrc

    # SNMP request for hostname
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public'),
               UdpTransportTarget((ip_address, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
    )

    if errorIndication:
        hostname = None
    else:
        hostname = varBinds[0][1].prettyPrint()

    # SNMP request for uptime
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public'),
               UdpTransportTarget((ip_address, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)))
    )

    if errorIndication:
        uptime = None
    else:
        uptime = varBinds[0][1].prettyPrint()

    # Add the information about the host to the list of active hosts
    active_hosts.append({'ip_address': ip_address, 'hostname': hostname, 'uptime': uptime})

# Print the results
for host in active_hosts:
    print("IP Address: ", host['ip_address'])
    print("Hostname: ", host['hostname'])
    print("Uptime: ", host['uptime'])
    print("\n")
```

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

from scapy.all import *

# Define the IP address range to scan
ip_range = '192.168.178.0/24'

# Create an ARP request packet
arp_request = ARP(pdst=ip_range)

# Send the ARP request and get the response
response = srp(arp_request, timeout=1, verbose=0)[0]

# Parse the response and print the results
for item in response:
    mac_address = item[1].hwsrc
    ip_address = item[1].psrc
    print(f'Found device with IP address: {ip_address} and MAC address: {mac_address}')

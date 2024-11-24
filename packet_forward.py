import socket
from sniffer import ethernet_head, get_ipv4_header, get_ip_addr 
import subprocess
import re

# Function to get the MAC address from the ARP table based on IP address
def mac_from_arp_table(ip_address):
    # Fetch the ARP table
    arp_table_call = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    arp_table_data = arp_table_call.stdout.decode()

    # Regular expression patterns to match IP and MAC addresses
    ip_pattern = re.compile(r'\b' + re.escape(ip_address) + r'\b')
    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[-:]){5}([0-9A-Fa-f]{2})')

    # Iterate through each line in the ARP table
    for line in arp_table_data.splitlines():
        if ip_pattern.search(line):
            mac_match = mac_pattern.search(line)
            if mac_match:
                # Return the MAC address without any separator (e.g., ":")
                return mac_match.group().replace(":", "").replace("-", "")
    
    print(f"MAC address for IP {ip_address} not found in ARP table!")
    return None

# Function to format a MAC address from a byte string to a human-readable format
def format_mac(mac_bytes):
    return ':'.join(['{:02x}'.format(b) for b in mac_bytes])

# In your Manipulate_packet function, format the MAC addresses before printing
def Manipulate_packet(raw_data):
    # Extract the Ethernet header (destination MAC, source MAC, protocol)
    target_mac, src_mac, proto, data = ethernet_head(raw_data)

    # Extract the IPv4 header from the packet
    ip_header = get_ipv4_header(data)

    # Convert the IP addresses from hex to string format
    src_ip = get_ip_addr(ip_header[4])
    target_ip = get_ip_addr(ip_header[5])

    # Get the real MAC addresses from the ARP table for source and destination IPs
    new_src_mac = mac_from_arp_table(src_ip)
    new_target_mac = mac_from_arp_table(target_ip)

    # If any MAC address is not found in the ARP table, print an error
    if new_src_mac is None or new_target_mac is None:
        print("Error: MAC address not found for one or both IP addresses!")
        return None

    # Convert the MAC addresses from string to bytes
    src_mac = bytes.fromhex(new_src_mac)
    target_mac = bytes.fromhex(new_target_mac)

    # Format the MAC addresses for better readability
    formatted_src_mac = format_mac(src_mac)
    formatted_target_mac = format_mac(target_mac)

    # Log the updated MAC addresses for debugging purposes
    print(f"Updated source MAC: {formatted_src_mac}, Updated target MAC: {formatted_target_mac}")

    # Rebuild the Ethernet frame with the new MAC addresses
    packet = target_mac + src_mac + raw_data[12:]

    # Print the raw and new packets for debugging
    print(f"Raw packet: {raw_data}")
    print(f"New packet (target + src mac): {formatted_target_mac} {formatted_src_mac}")

    return packet

def forward_packet(packet, interface):
    new_packet = Manipulate_packet(packet)

    if new_packet is not None:
        try:
            # Create a raw socket and bind to the interface
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.bind((interface, 0))
            s.send(new_packet)
            s.close()

        except Exception as e:
            print(f"Error forwarding packet: {e}")
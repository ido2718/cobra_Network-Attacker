
from sniffer import *
import subprocess
import re
#the function takes the mac address directly from the arp table
def mac_from_arp_table(ip_address):
    arp_table_call = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    arp_table_data=arp_table_call.stdout.decode()

    #Regular expressions for searching the arp table
    ip_pattern = re.compile(r'\b' + re.escape(ip_address) + r'\b')
    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[-:]){5}([0-9A-Fa-f]{2})')

    #search each line to find the ip address
    for line in  arp_table_data.splitlines():
        if ip_pattern.search(line):
            mac_match=mac_pattern.search(line)

            if mac_match:
                return mac_match.group()

            return None

#The function puts the real mac addresses in the packet
def Manipulate_packet(raw_data):
    #extrcat the ethernet header
    target_mac, src_mac, proto, data= ethernet_head(raw_data)
    #from the ethernet header extract the ip header
    ip_header=ipv4_header(data)

    #turning the ip address from hex to string
    src_ip=get_ip_addr(ip_header[4])
    target_ip=get_ip_addr(ip_header[5])

    #looking for the real mac address in the arp table
    new_src_mac=mac_from_arp_table(src_ip)
    new_target_mac=mac_from_arp_table(target_ip)

    #turning the string mac address to bytes(to put them in the packet)
    src_mac=bytes.fromhex(new_src_mac.replace(":",""))
    target_mac = bytes.fromhex(new_target_mac.replace(":", ""))

    #put the new mac address in the packet
    packet=target_mac + src_mac +raw_data[12:]

    return packet





def forward_packet(packet,interface):
    new_packet=Manipulate_packet(packet)

    if new_packet is not None:
        try:

            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.bind((interface, 0))
            s.send(new_packet)
            s.close()

        except Exception as e:
            print(f"Error forwarding packet: {e}")



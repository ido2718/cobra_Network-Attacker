import  sys
import socket
import struct
 

#covert Bytes mac address to a string
def get_mac_addr(bytes_addr):
    # Convert the bytes of MAC address to a string representation
    bytes_list = list(map('{:02x}'.format, bytes_addr))
    #Putting : between each byte
    mac_addr = ':'.join(bytes_list)
    return mac_addr
#covert Bytes ip address to a string
def get_ip_addr(addr):
    return '.'.join(map(str, addr))

#return parameters from the ethernet head
def ethernet_head(raw_data):
    #only the first 14 bytes are the ethernet header
    des_mac,source_mac,type=struct.unpack("!6s6sH",raw_data[:14])
    des_mac = get_mac_addr(des_mac)
    source_mac = get_mac_addr(source_mac)
    proto = socket.htons(type)
    #Extract data after the ethernet header
    data=raw_data[14:]
    return des_mac,source_mac,proto,data

#return parameters from the ICMP head
def icmp_head(raw_data):
    # icmp header size is 4 bytes
    icmp_type,icmp_code,icmp_checksum=struct.unpack("!2BH",raw_data[:4])
    #Extract data after the ICMP header
    data = raw_data[4:]
    return icmp_type,icmp_code,icmp_checksum,data

#return parameters from the TCP head
def tcp_head(raw_data):
    src_port, dest_port, sequence, acknowledgment, offset_and_reserved_flags = struct.unpack('!2H2LH', raw_data[:14])
    #first 4 bits are the offset(tcp header length)
    offset = (offset_and_reserved_flags >> 12) *4
    #last 6 bits are the flags
    flags = (offset_and_reserved_flags & 0b00111111)
    #seperate each flag
    flag_urg = (flags & 0b100000) >> 5
    flag_ack = (flags & 0b010000) >> 4
    flag_psh = (flags & 0b001000) >> 3
    flag_rst = (flags & 0b000100) >> 2
    flag_syn = (flags & 0b000010) >> 1
    flag_fin = flags & 0b000001
    #Extract data after the TCP header
    data = raw_data[14:]
    return src_port,dest_port,sequence,acknowledgment,offset,flag_fin,flag_syn,flag_rst,flag_psh,flag_ack,flag_urg,data


def udp_head(raw_data):
    # udp header size is 8 bytes
    source_p,dest_p,length,checksum=struct.unpack("!4H",raw_data[:8])
    #Extract data after the UDP header
    data = raw_data[8:]
    return source_p,dest_p,length,checksum,data

def get_ipv4_header(raw_data):
    #The first byte contain both the header and version
    version_ang_length=raw_data[0]
    #The first 4 bits are the version
    version=version_ang_length >> 4
    #The last 4 bits are the length
    length=(version_ang_length & 0b00001111) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    # Extract data after the IPv4 header
    data = raw_data[length:]
    return version, length, ttl, proto, src, target, data

#return parameters from the DNS head
def dns_head(raw_data):
    # Unpack DNS header
    transaction_id, flags, questions, answers, authority, additional = struct.unpack('!6H', raw_data[:12])
    # Extract data after the DNS header
    data = raw_data[12:]
    return transaction_id, flags, questions, answers, authority, additional, data

#return parameters from the ARP head
def arp_head(raw_data):
    # The ARP packet structure consists of several fields
    hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', raw_data[:8])

    # Check if it's an ARP request or reply based on the opcode
    arp_operation = "ARP Request" if opcode == 1 else "ARP Reply"

    sender_mac = get_mac_addr(raw_data[8:14])
    sender_ip = get_ip_addr(raw_data[14:18])
    target_mac = get_mac_addr(raw_data[18:24])
    target_ip = get_ip_addr(raw_data[24:28])

    return hardware_type, protocol_type, hardware_size, protocol_size, arp_operation, sender_mac, sender_ip, target_mac, target_ip
#print packet details
def anylaze_packet(raw_data):
    eth = ethernet_head(raw_data)
    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
    if eth[2] == 8:  # IPv4
        ipv4 = get_ipv4_header(eth[3])
        source = get_ip_addr(ipv4[4])
        target = get_ip_addr(ipv4[5])

        print('\t - IPv4 Packet:')
        print('\t\t - Version: {}, Header Length: {}, TTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
        print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], source, target))
        if ipv4[3] == 6:  # TCP
            print(ipv4[6])
            tcp = tcp_head(ipv4[6])
            print('\t\t - TCP Segment:')
            print('\t\t\t - Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
            print('\t\t\t - Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
            print('\t\t\t - Flags:')
            print('\t\t\t\t - URG: {}, ACK: {}, PSH: {}'.format(tcp[4], tcp[5], tcp[6]))
            print('\t\t\t\t - RST: {}, SYN: {}, FIN: {}'.format(tcp[7], tcp[8], tcp[9]))

            if len(tcp[10]) > 0:
                print('\t\t - TCP Data:')

            if tcp[1] == 80:
                print('\t\t - HTTP Traffic (port 80)')
                #covert the http part into string

                try:
                    http_text = tcp[11].decode('utf-8')
                    print(http_text)

                except UnicodeDecodeError:
                    print("\t\t - Non-UTF-8 Data")

            elif tcp[1] == 443:
                print('\t\t - HTTPS Traffic (port 443)')

        elif ipv4[3] == 1:  # ICMP
            icmp = icmp_head(ipv4[6])
            print('\t\t - ICMP Packet:')
            print('\t\t\t - Type: {}, Code: {}, Checksum: {}'.format(icmp[0], icmp[1], icmp[2]))

            if len(icmp[3]) > 0:
                print('\t\t - ICMP Data:')

        elif ipv4[3] == 17:  # UDP
            udp = udp_head(ipv4[6])
            print('\t\t - UDP Segment:')
            print('\t\t\t - Source Port: {}, Destination Port: {}'.format(udp[0], udp[1]))
            print('\t\t\t - Length: {}, Checksum: {}'.format(udp[2], udp[3]))

            if udp[1] == 53: #DNS
                dns = dns_head(udp[4])
                print('\t\t\t - DNS Packet:')
                print('\t\t\t\t - Transaction ID: {}'.format(dns[0]))
                print('\t\t\t\t - Flags: {}'.format(dns[1]))
                print('\t\t\t\t - Questions: {}'.format(dns[2]))
                print('\t\t\t\t - Answers: {}'.format(dns[3]))
                print('\t\t\t\t - Authority: {}'.format(dns[4]))
                print('\t\t\t\t - Additional: {}'.format(dns[5]))

    elif eth[2] == 1544:  # ARP
        arp = arp_head(eth[3])
        print('\t - ARP Packet:')
        print('\t\t - Hardware Type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
        print('\t\t - Hardware Size: {}, Protocol Size: {}'.format(arp[2], arp[3]))
        print('\t\t - Operation: {}'.format(arp[4]))
        print('\t\t - Sender MAC: {}, Sender IP: {}'.format(arp[5], arp[6]))
        print('\t\t - Target MAC: {}, Target IP: {}'.format(arp[7], arp[8]))

#the function will sniff and forward packets


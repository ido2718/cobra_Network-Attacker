from sniffer import anylaze_packet,ethernet_head,get_ip_addr,get_ipv4_header
from packet_forward import forward_packet
import socket 
def sniff_packets(interface,target1_ip,target2_ip):
    #create a raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data,addr= s.recvfrom(65535)
        eth=ethernet_head(raw_data)
        #if the network header is ipv4
        if eth[2]== 8:
            ipv4_header=get_ipv4_header(eth[3])
            target_ip=get_ip_addr(ipv4_header[4])
            source_ip=get_ip_addr(ipv4_header[5])
            print(f"{target_ip}{source_ip}") 

            #if the packet is between the spoof ip and the target ip we will print the packet details and  forward the packet
            if (target1_ip==target_ip and target2_ip==source_ip) or (target2_ip==target_ip and target1_ip==source_ip):
                anylaze_packet(raw_data)
                forward_packet(raw_data,interface)
                

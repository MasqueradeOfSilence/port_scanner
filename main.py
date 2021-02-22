#!/usr/bin/sudo python

import traceback

import scapy
import sys
from datetime import datetime
from time import strftime
from logging import getLogger, ERROR

# Thanks, PyCharm.
from scapy.config import conf
from scapy.layers.inet import ICMP, TCP
from scapy.sendrecv import sr1, send
from scapy.layers.inet import IP
from scapy.volatile import RandShort


def check_valid_ip(ip_list):
    for ip in ip_list:
        ip = ip.split(".")
        if len(ip) > 4:
            # We will not be handling IPv6 in this program
            print("Oops! IPv4 is too long. Please try again.")
            return False
        elif len(ip) < 4:
            print("Oops! IPv4 is too short or contains invalid characters. Please try again.")
            return False
        for i in range(0, len(ip)):
            current = ip[i]
            if "/" in current:
                temp = current.split("/")
                current = temp[0]
            try:
                test = int(current)
            except ValueError:
                print("Non-integer value detected!")
                return False
            if int(current) < 0 or int(current) > 255:
                print("Oops! One or more of your IP numbers is out of range. Please try again.")
                return False
    return True


def is_valid_port(port_entered):
    try:
        port_entered = int(port_entered)
    except ValueError:
        print("Oops! Port should be a numerical value!")
    return 65354 > port_entered >= 0


# Note: Subnet mask must be written in 255... form
def compute_host_range(ip, subnet_mask):
    ip_list = [ip, subnet_mask]
    if not check_valid_ip(ip_list):
        print("Error: invalid IP entered")
        sys.exit(1)
    subnet_numbers = subnet_mask.split(".")
    magic_number = 255
    magic_index = 0
    # Find the first number that isn't 255
    for index, number in enumerate(subnet_numbers):
        try:
            number = int(number)
        except ValueError:
            print("Subnet must be a number!")
            sys.exit(1)
        if number < 255:
            print("Here is number: " + str(number))
            magic_number = abs(number - 256)
            print("index: " + str(index))
            magic_index = index
            break
    split_ip = ip.split(".")
    result = int(split_ip[magic_index]) // magic_number
    result2 = int(result * magic_number)
    octet = result2 + magic_number - 1
    min_ip = "192.168.1.1"
    max_ip = "192.168.1.1"
    if magic_index == 2:
        min_ip = split_ip[0] + "." + split_ip[1] + "." + str(result2) + ".0"
        max_ip = split_ip[0] + "." + split_ip[1] + "." + str(octet) + ".255"
    elif magic_index == 3:
        min_ip = split_ip[0] + "." + split_ip[1] + "." + split_ip[2] + "." + str(result2)
        max_ip = split_ip[0] + "." + split_ip[1] + "." + split_ip[2] + "." + str(octet)
    elif magic_index == 1:
        min_ip = split_ip[0] + "." + str(result2) + "." + split_ip[2] + "." + split_ip[3]
        max_ip = split_ip[0] + "." + str(octet) + "." + split_ip[2] + "." + split_ip[3]
    elif magic_index == 0:
        min_ip = str(result2) + "." + split_ip[1] + "." + split_ip[2] + "." + split_ip[3]
        max_ip = str(octet) + "." + split_ip[1] + "." + split_ip[2] + "." + split_ip[3]
    else:
        print("Oops, something went wrong! Exiting...")
        sys.exit(1)
    print("Min IP: " + min_ip)
    print("Max IP: " + max_ip)
    return min_ip, max_ip


# Try to ping with a single packet to make sure that the target is up
# Must run PyCharm as administrator to ensure this works
def check_if_host_is_up(ip):
    try:
        print("Setting up ping for IP " + ip + ".")
        ping = sr1(IP(dst=ip) / ICMP(), timeout=10, iface="eth0", verbose=False)
        print("Ping successful! Beginning scan...")
    except Exception as e:
        print("Couldn't ping! Exiting...")
        print("The error: " + str(e))
        traceback.print_exc()
        sys.exit(1)


def synack_received(flags):
    SYNACK = 0x12
    return flags == SYNACK


# Sending the RST packet will terminate our connection as soon as we've gotten what we need.
def send_rst_packet(source_port, dest_port, ip):
    rst_packet = IP(dst=ip) / TCP(sport=source_port, dport=dest_port, flags="R")
    send(rst_packet)


def scan_port(port, ip):
    # Just generate a random source port
    source_port = RandShort()
    conf.verb = 0
    # The sr1 command is how we will send our SYN packet (using the S flag), and we hope to receive a SYNACK back
    # If we do, the destination port is open
    synack_packet = sr1(IP(dst=ip) / TCP(sport=int(source_port), dport=int(port), flags="S"))
    received_flags = synack_packet.getlayer(TCP).flags
    send_rst_packet(int(source_port), int(port), ip)
    if synack_received(received_flags):
        return True
    else:
        return False


def conclude_scan(start_clock):
    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    print("Finished scanning in " + str(total_time) + "!")


def scan_single_port(port, ip):
    check_if_host_is_up(ip)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    port_open = scan_port(port, ip)
    at_least_one_port_open = False
    if port_open:
        print("Port " + str(port) + " is open on " + ip)
        at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def scan_ports_list(ports_list, ip):
    check_if_host_is_up(ip)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    at_least_one_port_open = False
    for port in ports_list:
        port_open = scan_port(port, ip)
        if port_open:
            print("Port " + str(port) + " is open on " + ip)
            at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def scan_range_of_ports(min_port, max_port, ip):
    check_if_host_is_up(ip)
    # Include the max_port with +1
    ports_list = range(int(min_port), int(max_port) + 1)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    at_least_one_port_open = False
    for port in ports_list:
        port_open = scan_port(port, ip)
        if port_open:
            print("Port " + str(port) + " is open on " + ip)
            at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def get_user_input():
    # Use a try-catch loop to allow the user to CTRL+C and exit
    try:
        valid_ip = False
        # Just using gateway as default: this will be overwritten
        ip_addresses = ["192.168.1.1"]
        while not valid_ip:
            ip_addresses = input(
                "Enter comma-separated list of IPv4 Addresses that you want to scan, or a .txt file separated by "
                "newlines, or s for subnet mask option with 255 prefix (for CIDR notation, just enter IP/number): ")
            if ip_addresses.lower() == "s":
                ip = input("Enter IP: ")
                subnet_mask = input("Enter subnet in 255.x.x.x form only: ")
                min_ip, max_ip = compute_host_range(ip, subnet_mask)
                # Insert everything from min_ip to max_ip into ip_addresses
                ip_addresses = [min_ip + "-" + max_ip]
                temp_addresses = [min_ip, max_ip]
                valid_ip = check_valid_ip(temp_addresses)
            elif ".txt" in ip_addresses:
                new_ips = []
                print("Reading from file" + ip_addresses + "...")
                try:
                    file = open(ip_addresses, "r")
                    for line in file:
                        # Ignore whitespace
                        if line.strip():
                            new_ips.append(line)
                    ip_addresses = new_ips
                    valid_ip = check_valid_ip(ip_addresses)
                except FileNotFoundError:
                    print("Oops! File not found! Please try again!")
            else:
                ip_addresses = ip_addresses.split(",")
                valid_ip = check_valid_ip(ip_addresses)
        # Single port, port range, multiple ports
        valid_option = False
        port_option = "Default"
        while not valid_option:
            port_option = input("Enter S for single port, M for multiple ports, P for port range: ")
            port_option = port_option.lower()
            if port_option == "s":
                valid_option = True
            elif port_option == "m":
                valid_option = True
            elif port_option == "p":
                valid_option = True
            else:
                print("Invalid option; please try again!")
        # Next, make sure their formatting is correct for S/M/P options
        ok_port_entered = False
        while not ok_port_entered:
            if port_option == "Default":
                print("Error with port selection. Aborting.")
                sys.exit(1)
            if port_option == "s":
                port_entered = input("Enter port number: ")
                # Check for valid ports
                if is_valid_port(port_entered):
                    ok_port_entered = True
                    for ip_address in ip_addresses:
                        ip_address = ip_address.strip()
                        scan_single_port(port_entered, ip_address)
            elif port_option == "m":
                ports_entered = input("Enter ports separated by a comma: ")
                ports_list = ports_entered.split(",")
                # Set it to true unless one of our ports is invalid
                ok_port_entered = True
                for port in ports_list:
                    if not is_valid_port(port):
                        ok_port_entered = False
                if ok_port_entered:
                    for ip_address in ip_addresses:
                        ip_address = ip_address.strip()
                        scan_ports_list(ports_list, ip_address)
            elif port_option == "p":
                min_port = input("Enter minimum port number: ")
                max_port = input("Enter maximum port number: ")
                if min_port.isdigit() and max_port.isdigit() and is_valid_port(min_port) and is_valid_port(
                        max_port) and int(min_port) < int(max_port):
                    ok_port_entered = True
                    for ip_address in ip_addresses:
                        ip_address = ip_address.strip()
                        scan_range_of_ports(min_port, max_port, ip_address)

            if not ok_port_entered:
                print("Invalid port(s)! Please try again.")

    except KeyboardInterrupt:
        print("\nInterrupt detected. Exiting...")
        sys.exit(1)


# Set log level to error
getLogger("scapy.runtime").setLevel(ERROR)
print("Hello port scanner!")

get_user_input()

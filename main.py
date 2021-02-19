import scapy
import sys
from datetime import datetime
from time import strftime
from logging import getLogger, ERROR


def check_valid_ip(ip):
    ip = ip.split(".")
    if len(ip) > 4:
        # We will not be handling IPv6 in this program
        print("Oops! IPv4 is too long. Please try again.")
        return False
    elif len(ip) < 4:
        print("Oops! IPv4 is too short. Please try again.")
        return False
    for i in range(0, len(ip)):
        current = ip[i]
        if int(current) < 0 or int(current) > 255:
            print("Oops! One or more of your IP numbers is out of range. Please try again.")
            return False
    return True


def is_valid_port(port_entered):
    if not port_entered.isdigit():
        return False
    port_entered = int(port_entered)
    return 65354 > port_entered >= 0


def get_user_input():
    # Use a try-catch loop to allow the user to CTRL+C and exit
    try:
        valid_ip = False
        while not valid_ip:
            ip_address = input("Enter IPv4 Address you want to scan: ")
            valid_ip = check_valid_ip(ip_address)
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
            elif port_option == "m":
                ports_entered = input("Enter ports separated by a comma")
                ports_list = ports_entered.split(",")
                # Set it to true unless one of our ports is invalid
                ok_port_entered = True
                for port in ports_list:
                    if not is_valid_port(port):
                        ok_port_entered = False
            elif port_option == "p":
                min_port = input("Enter minimum port number: ")
                max_port = input("Enter maximum port number: ")
                if min_port.isdigit() and max_port.isdigit() and is_valid_port(min_port) and is_valid_port(max_port) and int(min_port) < int(max_port):
                    ok_port_entered = True

            if not ok_port_entered:
                print("Invalid port(s)! Please try again.")

    except KeyboardInterrupt:
        print("\nInterrupt detected. Exiting...")
        sys.exit(1)


# Set log level to error
getLogger("scapy.runtime").setLevel(ERROR)
print("Hello port scanner!")

get_user_input()

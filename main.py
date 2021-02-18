import scapy
import sys
from datetime import datetime
from time import strftime
from logging import getLogger, ERROR


def get_user_input():
    # Use a try-catch loop to allow the user to CTRL+C and exit
    try:
        ip_address = input("Enter IP Address you want to scan: ")
        # Single port, port range, multiple ports
        valid_option = False
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
            ok_port_entered = False

    except KeyboardInterrupt:
        print("\nInterrupt detected. Exiting...")
        sys.exit(1)


# Set log level to error
getLogger("scapy.runtime").setLevel(ERROR)
print("Hello port scanner!")

get_user_input()

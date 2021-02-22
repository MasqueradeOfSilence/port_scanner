#!/usr/bin/sudo python

import traceback

import scapy
import sys
import PySimpleGUI as sg
from datetime import datetime
from time import strftime
from logging import getLogger, ERROR
from os import path

# Thanks, PyCharm.
from scapy.config import conf
from scapy.layers.inet import ICMP, TCP, UDP, traceroute
from scapy.sendrecv import sr1, send
from scapy.layers.inet import IP
from scapy.volatile import RandShort

final_report_string = ""


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
    print("Running TCP scan...")
    synack_packet = sr1(IP(dst=ip) / TCP(sport=int(source_port), dport=int(port), flags="S"))
    received_flags = synack_packet.getlayer(TCP).flags
    send_rst_packet(int(source_port), int(port), ip)
    if udp_scan(port, ip):
        return True
    if synack_received(received_flags):
        return True
    else:
        return False


def udp_scan(port, ip):
    print("Running UDP scan...")
    port = int(port)
    result = sr1(IP(dst=ip) / UDP(sport=RandShort(), dport=port), verbose=0, timeout=3)
    if result and result.haslayer(UDP):
        return True
    return False


def conclude_scan(start_clock):
    global final_report_string
    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    print("Finished scanning in " + str(total_time) + "!")
    html_report = open("report.html", "w")
    html_report.write(final_report_string)
    html_report.close()
    print("Data written to report.html!")


def scan_single_port(port, ip):
    global final_report_string
    check_if_host_is_up(ip)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    port_open = scan_port(port, ip)
    at_least_one_port_open = False
    if port_open:
        summary_open = "Port " + str(port) + " is open on " + ip
        print(summary_open)
        final_report_string += "\n<p>" + summary_open + "</p>"
        at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def scan_ports_list(ports_list, ip):
    global final_report_string
    check_if_host_is_up(ip)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    at_least_one_port_open = False
    for port in ports_list:
        port_open = scan_port(port, ip)
        if port_open:
            summary_open = "Port " + str(port) + " is open on " + ip
            print(summary_open)
            final_report_string += "\n<p>" + summary_open + "</p>"
            at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def scan_range_of_ports(min_port, max_port, ip):
    global final_report_string
    check_if_host_is_up(ip)
    # Include the max_port with +1
    ports_list = range(int(min_port), int(max_port) + 1)
    start_clock = datetime.now()
    print("Beginning scan for " + ip + "...")
    at_least_one_port_open = False
    for port in ports_list:
        port_open = scan_port(port, ip)
        if port_open:
            summary_open = "Port " + str(port) + " is open on " + ip
            print(summary_open)
            final_report_string += "\n<p>" + summary_open + "</p>"
            at_least_one_port_open = True
    if not at_least_one_port_open:
        print("No open ports found on " + ip + "!")
    conclude_scan(start_clock)


def gui_input():
    global final_report_string
    final_report_string += "<h1>Summary of Port Scan</h1>\n"
    print("GUI option selected! Launching GUI!")
    layout = [[sg.Text("Enter the IP address and port(s)! Can also add subnet in CIDR notation")],
              [sg.Text("IPs (Comma-Separated List)", size=(25, 1)), sg.InputText()],
              [sg.Text("Ports (Comma-Separated List)", size=(25, 1)), sg.InputText()],
              [sg.Checkbox("Run traceroute", default=True)],
              [sg.Text("Optional: choose a .txt file with newline-separated list of IPs", key="BROWSE"), sg.FileBrowse(key="-IN-")],
              [sg.Button("SCAN")]]
    window = sg.Window("Port Scanner", layout)
    while True:
        event, values = window.read()
        # Scan logic
        if event == "BROWSE":
            print("Browsing event")
        if event == "SCAN":
            ip_addresses = values[0]
            ports_list = values[1]
            should_run_traceroute = values[2]
            ip_addresses = ip_addresses.split(", ")
            specified_file = values["-IN-"]
            if specified_file != "":
                print("Scanning the following file for IP addresses: ")
                print(specified_file)
                try:
                    f = open(specified_file, "r")
                    for line in f:
                        if line.strip():
                            ip_addresses.append(line)
                except FileNotFoundError:
                    sg.Popup("Invalid file! Exiting...")
                    break
            are_ips_valid = check_valid_ip(ip_addresses)
            if not are_ips_valid:
                sg.Popup("Oops! Invalid IPs! Please try again!")
            else:
                if should_run_traceroute:
                    for ip in ip_addresses:
                        traceroute(ip)
                valid_ports = True
                ports_list = ports_list.split(", ")
                for port in ports_list:
                    try:
                        port = int(port)
                    except ValueError:
                        sg.Popup("Oops! Ports should be a number! Please try again!")
                        valid_ports = False
                        break
                    if not is_valid_port(port):
                        sg.Popup("Oops! Invalid port found! Please try again!")
                        valid_ports = False
                        break
                if not valid_ports:
                    break
                else:
                    for ip in ip_addresses:
                        scan_ports_list(ports_list, ip)
            break
        elif event == sg.WIN_CLOSED:
            break
    window.close()


def get_user_input():
    global final_report_string
    final_report_string += "<h1>Summary of Port Scan</h1>\n"
    # Use a try-catch loop to allow the user to CTRL+C and exit
    try:
        valid_ip = False
        # Just using gateway as default: this will be overwritten
        ip_addresses = ["192.168.1.1"]
        while not valid_ip:
            ip_addresses = input(
                "Enter comma-separated list of IPv4 Addresses that you want to scan, or a .txt file separated by "
                "newlines. Feel free to specify a subnet in CIDR notation: ")
            if ".txt" in ip_addresses:
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
        # Traceroute option
        traceroute_option_selected = False
        while not traceroute_option_selected:
            should_traceroute = input("Would you like to run traceroute on all IPs? Y/N ")
            if should_traceroute.lower() == "y" or should_traceroute.lower() == "yes" or should_traceroute.lower() == "oui oui":
                traceroute_option_selected = True
                for ip_address in ip_addresses:
                    traceroute(ip_address)
            elif should_traceroute.lower() == "n" or should_traceroute.lower() == "no":
                traceroute_option_selected = True
            else:
                print("Invalid option selected. Please try again!")
        valid_option = False
        port_option = "Default"
        # Single port, port range, multiple ports
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

gui_or_cli = input("Welcome to the port scanner! Enter g for GUI, and anything else for CLI! ")
if gui_or_cli.lower() == "g":
    gui_input()
else:
    get_user_input()

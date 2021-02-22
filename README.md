# port_scanner
IT 567 Assignment 3

Instructions: I ran this from the CLI using sudo python3 main.py. 

There are both GUI and CLI options for running the program. The program is initially run from the CLI, but an interactive GUI can be launched on command at the beginning if you enter "g". 

On the CLI you are allowed to scan port ranges, as well as single or multiple ports. On the GUI I only implemented functionality to scan single or multiple ports, separated by commas (so no port ranges for the GUI-side). 

The following features are implemented: 
- Basic port scanning functionality 
- Scanning multiple hosts
- Reading multiple IPs from the CLI
- Reading a text file of IPs from the CLI (or from the GUI)
- Allowing the user to specify a port via subnet mask/range with CIDR notation
- Use of ICMP, TCP, and UDP protocols
- Traceroute (optional, but user is prompted on both GUI and CLI)
- HTML report generated at the end
- GUI functionality

import nmap
import os
import sys
# Create an nmap scanner object
nm = nmap.PortScanner()

# Prompt the user for the IP address
ip_address = input("Enter the IP address of the network device : ")

# Scan the host for vulnerabilities
nm.scan(ip_address, '22-443')

# Print the results
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = list(nm[host][proto].keys())  # convert dict_keys to list
        lport.sort()  # sort the list
        for port in lport:
            # Add OS detection
            if 'osclass' in nm[host][proto][port]:
    # Check for OS class
                os_class = nm[host][proto][port]['osclass']
                os_match = nm[host][proto][port]['osmatch']
                print('port : %s\tstate : %s\tOS Class : %s\tOS Match : %s' % (port, nm[host][proto][port]['state'], os_class, os_match))
            else:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))





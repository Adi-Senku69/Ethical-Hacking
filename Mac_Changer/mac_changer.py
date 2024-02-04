#! /usr/bin/env python

import subprocess
import optparse
import re


def get_arguments() -> tuple:
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("Please specify an MAC address, use --help for more info")

    return (options, arguments)
def change_mac(interface: str, new_mac: str) -> None:
    print(f"Changing MAC address for {interface} to {new_mac}")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    subprocess.call("ifconfig", shell=True)

# interface = input("Enter the interface name ")
# new_mac = input("Enter the new MAC Address ")


(options, arguments) = get_arguments()

# change_mac(options.interface, options.new_mac)

ifconfig_result = str(subprocess.check_output(["ifconfig",options.interface]))
mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

if mac_address_search_result:
    print(mac_address_search_result.group(0))
else:
    print("Could not get MAC address")

# subprocess.call(f"ifconfig {interface} down", shell=True)
# subprocess.call(f"ifconfig {interface} hw ether {new_mac}", shell=True)
# subprocess.call(f"ifconfig {interface} up", shell=True)
# subprocess.call("ifconfig", shell=True)

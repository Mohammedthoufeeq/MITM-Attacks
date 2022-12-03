# MITM-Attacks
Man In the Middle Attack Using Python 

This is a simple tool for poisoning the arp protocol by spoofing router.

It Contains two scripts :
      
      1. Arp Poisoning Script - Spoofs the IP Address and Mac Address
      2. Sniffer Script - It Captures passwords and username (Only if victim uses http websites)


**Requirements :**

Python 3.x

Pip packages - scapy,time

pip install scapy

**Installation :**

git clone https://github.com/Mohammedthoufeeq/MITM-Attacks/


**Usage :**

cd MITM-Attacks

To spoof,
  python arpspoof.py -t target_ip -r router_ip

To sniff,
  python sniifer.py 

**Note : Sniffer only works if "arpspoof.py" is running on background in another terminal.**



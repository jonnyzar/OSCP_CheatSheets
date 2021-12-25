#!/usr/bin/env python3
"""
Analyze traffic to detect Spoofed IPs

task rewrite using tcpdump as input stream

typical default TTL for LINUX = 64; WIN = 128
"""


from scapy.all import *
from IPy import IP as IPTEST
ttlValues = {}
THRESH = 5

def checkTTL (ipsrc, ttl):
    #checks ttl from ICMP response with ttl from original pckg (ipsrc)
    if IPTEST(ipsrc).private == 'PRIVATE':
        return
    #check if ipsrc is already in the dictionary and was analyzed
    if not ipsrc in ttlValues:
        #send ICMP pckt to the incomming src and wait for 1 answer
        pkt = sr1(IP(dst=ipsrc) / ICMP(), retry=0,timeout=1,verbose=0)
        ttlValues[ipsrc] = pkt.ttl
    #calculate difference between ttl from ICMP resp and src ttl
    if abs(int(ttl) - int(ttlValues[ipsrc])) > THRESH:
        print(f"May be Spoofing from {ipsrc}")
        print(f"Inc TTL={ttl}, Suspicious TTL={ttlValues[ipsrc]}")

def testTTL(pkt):
    try:
        if pkt.haslayer(IP):
            ipsrc = pkt.getlayer(IP).src
            ttl = str(pkt.ttl)#get ttl from packet
            checkTTL(ipsrc, ttl)
            #print (f"[+] TCP packet from {ipsrc} with TTL={ttl}")
    except:
        pass

def main():
    #lets capture some traffic
    #sniff is slow, can miss traffic -> use tcpdump if possible
    #sniff(prn=testTTL, store=0)
    
    #Implement here the argparse and run functions from above


    return 0

if __name__ == "__main__":
    main()

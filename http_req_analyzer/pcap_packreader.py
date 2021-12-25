#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

import dpkt
import socket

class Pktread:
    """
    This class is for reading data from .pcap packages
    """

    def __init__(self,pcapfile_path):
        """
        ATTENTION: use only tcpdump-type files!
        """
        self.fpath = pcapfile_path

    def track_get(self,pattern):
        """
        track GET requests that contain <pattern> passed as regular expression
        regex support to be implemented...
        """
        f = open(self.fpath,'rb') #open in read bytes mode
        pcap = dpkt.pcap.Reader(f)#pass to dpkt Reader to extract infromation

        for (ts,buf) in pcap:     
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                src = socket.inet_ntoa(ip.src) #convert ip from 32bit to doted format    
                tcp = ip.data
                http = dpkt.http.Request(tcp.data)
                if http.method == "GET":
                    uri = http.uri.lower()
                    print(uri)
                    #list any additional malware name patterns like "loic"
                    if pattern in uri:
                        print(f"[!] {src} requested content.")
            except:
                pass

        f.close()


    def get_IPs(self):
        """
        add manual
        """
        f = open(self.fpath,'rb') #open in read bytes mode
        pcap = dpkt.pcap.Reader(f)#pass to dpkt Reader to extract infromation


        src_IPs = []#will hold source ip addresses
        dst_IPs = []#-//- destination ip addresses

        
        for (ts,buf) in self.pcap:     
            #to filter out Layer2 only packets
            #if log line does not contain layer3 info then it will be passed
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                src = socket.inet_ntoa(ip.src) #convert ip from 32bit to doted format    
                dst = socket.inet_ntoa(ip.dst)  
                src_IPs.append(src)
                dst_IPs.append(dst)
                                            
            except:
                pass
        
        f.close()
        return src_IPs, dst_IPs 
        
        
                
                
                
                
                

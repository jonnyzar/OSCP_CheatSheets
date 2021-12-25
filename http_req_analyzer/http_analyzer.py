#!/usr/bin/env python3

"""
Searches HTTP for GET requests

Use dpkt:
    1. extract Eth, IP, TCP layers
    2. locate GET request and extract URI from it
    3. extract further features from the GET request to identify the source
"""

from pcap_packreader import Pktread 





def main():
    pcap_file = "example.pcap" 
    pkts = Pktread(pcap_file)
    pkts.track_get("")

    return 0


if __name__ == "__main__":
    main()

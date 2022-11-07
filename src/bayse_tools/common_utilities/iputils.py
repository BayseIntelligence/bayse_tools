"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains utility functions that work with IP addresses.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""

import ipaddress
import pcapy
from bayse_tools.common_utilities import packet


def check_if_local_ip(ip_address):
    """Helper function to figure out if the provided IP address is local, private, multicast, etc...
    """
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_link_local  # we only want to work with globally-routable IPs, essentially

def collect_active_external_ips_from_capture_file(utils):
    """We want to know which IP addresses are actually active in a given input file, so we figure that out here. Active
       means that there was actually traffic to/from them, rather than just a DNS lookup that returned that IP
       address.
    """

    if len(utils.active_external_ips) > 0:
        print("Warning: there are already active external IPs stored. Results may differ from expectations.")
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        try:
            (hdr, pkt) = capfile.next()
        except:
            print("Got unparseable packet. Trying again")
            (hdr, pkt) = capfile.next()
        while hdr is not None:
            pkt_len = len(pkt)
            if pkt_len >= 34:  # length of IPv4 packet with standard header
                try:
                    if (pkt[0] == 0 and pkt[4:6] == b"\x00\x06" and pkt[14:16] == b"\x08\x00"):
                        #this IP packet has a Linux-cooked header, so ignore first 2 bytes
                        pkt = pkt[2:]
                    packet_info = packet.PacketInfo(pkt, hdr, utils)  # instantiate for ability to use utilities
                    ip_a = packet_info.source_ip
                    ip_b = packet_info.dest_ip
                    if check_if_local_ip(ip_a):
                        pass
                    else:
                        utils.active_external_ips.add(ip_a)
                    if check_if_local_ip(ip_b):
                        pass
                    else:
                        utils.active_external_ips.add(ip_b)
                except:
                    print("IP addresses not found in expected byte range for this packet. Skipping.")
            hdr, pkt = capfile.next()


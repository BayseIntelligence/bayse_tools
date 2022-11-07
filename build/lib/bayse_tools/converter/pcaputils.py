"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains utilities that make processing a .cap, .pcap, or .pcapng file easy to do. Ultimately, the final
    function in this file will create BayseFlows out of the incoming capture data.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""

import re
import sys
import magic
import pcapy
from bayse_tools.common_utilities import captureutils


def filter_capture_file_by_bpf(utils, bpf_to_apply):
    """Takes a Berkeley packet filter (BPF) and applies it to the capture file. Whatever remains after the BPF is
       applied will be saved to the output file.
    """
    last_dot = utils.original_filepath.rfind(".")
    if last_dot == -1:  # no extension in file name
        utils.filtered_filepath = utils.original_filepath + "_filtered"
    else:
        utils.filtered_filepath = utils.original_filepath[:last_dot] + "_filtered" + utils.original_filepath[last_dot:]
    capfile = pcapy.open_offline(utils.original_filepath)
    output = capfile.dump_open(utils.filtered_filepath)
    capfile.setfilter(bpf_to_apply)
    try:
        (hdr, pkt) = capfile.next()
    except:
        print("Got unparseable packet. Trying again")
        (hdr, pkt) = capfile.next()

    while hdr is not None:
        output.dump(hdr, pkt)
        try:
            (hdr, pkt) = capfile.next()
        except:
            print("Got unparseable packet. Trying again")
            (hdr, pkt) = capfile.next()
    del output


def remove_local_traffic_from_capture_file(utils, dnshelper):
    """No longer used for creation of BayseFlows, as all traffic is intended to be labeled.  Calls most of the
       functions to prepare and then remove the local traffic from the incoming capture file.
    """

    bpf_to_apply = ""  # set up the empty BPF

    """Remove all of the local/uninteresting traffic
         Steps:

         1. Get all of the DNS queries in form <port> <dns.qry.name> <dns.resp.name>
    """
    dnshelper.parse_dns_records_from_capture_file()

    """2. Identify which of the DNS queries are either local forward or local reverse lookups (looking for
          things in RFC1918 and similar IP address ranges). Note that this currently only works for IPv4.
    """
    local_lookups = dnshelper.collect_local_lookups()

    """3. Create a valid Berkeley Packet Filter (BPF) to exclude all local protocols (those that communicate only on
          internal networks, or that have sensitive-but-uninteresting [to us] data when communicated externally).
    """
    local_protocols = "445 or 5355 or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or 1900"

    """4. Create a BPF that confirms that at least one IP address in EVERY conversation is NOT local (still only works
          for IPv4).
    """
    local_to_local_sans_dns = "(src net 0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8) and (dst net (0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8)) and not port domain"

    """5. Create a BPF that excludes DNS resolutions using internal resolvers, and explicitly excludes those
          local lookups (by destination port) that we found earlier.
    """
    dns_prefix = " and not (port domain and (src net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12) and (dst net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12)"

    dns_expression = ""
    if len(local_lookups) > 0:
        dns_expression += (dns_prefix + " and port (" + "".join(local_lookups) + "))")

    """6. Assemble the full BPF that (in English) does the following:
            MUST be IP and no SMB or any other E-W protocols and no non-DNS local-to-local traffic and no local-to-local
            DNS traffic with local lookups and no IPv6 (since we do not handle IPv6 today).
    """
    bpf_to_apply = "ip and ((not port (" + local_protocols + ")) and not (" + local_to_local_sans_dns + ") " + dns_expression + " and not ip6)"

    """7. Filter the capture file using the assembled BPF, and then return the filtered file location for use in the
          rest of the pipeline.
    """
    filter_capture_file_by_bpf(utils, bpf_to_apply)


def validate_file_format(utils):
    """Validate that the file is of an accepted type (CAP, PCAP, or PCAPNG).
    """

    # check if file is valid
    utils.file_format = magic.from_file(utils.original_filepath)
    if not re.match(r"^(p|)cap(|(|\-)ng) capture file", utils.file_format):
        print("Error:", utils.original_filepath + ",", "of type", utils.file_format,
              "is not an accepted file type.")
        sys.exit(1)


def pcap_to_bayseflow_converter(utils, dnshelper):
    """Given a capture file that has been validated, collect the BayseFlows for all TCP, UDP, and ICMP/ICMPv6 sessions.
    """
    # get all of the DNS queries in form <port> <dns.qry.name> <dns.resp.name>
    dnshelper.parse_dns_records_from_capture_file()

    bpf_to_apply = "tcp or udp or icmp or icmp6 or ip or ip6"

    """Filter the capture file using the assembled BPF, and then return the filtered file location for use in the rest
       of the pipeline.
    """
    filter_capture_file_by_bpf(utils, bpf_to_apply)

    get_min_timestamp_from_capture_file(utils)

    # get all of the UDP records in place
    parse_bayseflows_from_capture_file(utils, "udp")

    # get all of the TCP records in place
    parse_bayseflows_from_capture_file(utils, "tcp")

    # get all of the ICMP/ICMPv6 records in place
    parse_bayseflows_from_capture_file(utils, "icmp or icmp6")

    # get all of the IP/IPv6 non-TCP or UDP records (like GRE, IPIP) in place
    parse_bayseflows_from_capture_file(utils, "not udp and not tcp and (ip or ip6)")


def get_min_timestamp_from_capture_file(utils):
    """Iterates through the file to find the absolute minimum timestamp.
    """
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        capfile.setfilter("udp or tcp or icmp or icmp6 or ip or ip6")
        try:
            (hdr, pkt) = capfile.next()
        except:
            print("Got unparseable packet. Trying again")
            (hdr, pkt) = capfile.next()
        while hdr is not None:
            # update start time with the actual file min
            utils.file_start_time = min(utils.file_start_time, utils.get_timestamp_from_packet_header(hdr))
            try:
                (hdr, pkt) = capfile.next()
            except:
                print("Got unparseable packet. Trying again")
                (hdr, pkt) = capfile.next()


def parse_bayseflows_from_capture_file(utils, protocol):
    """Takes a capture file and a transport protocol, and uses other functions to parse all relevant packets to find
       the directionality of the sessions to which they belong. Creates and returns an ordered dictionary
       of BayseFlows.
    """
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        if not re.match("^(tcp|udp|(icmp or icmp6)|(not udp and not tcp and \\(ip or ip6\\)))$", protocol):
            print(f"Error, protocol {protocol} not supported!")
            return
        capfile.setfilter(protocol)
        try:
            (hdr, pkt) = capfile.next()
        except:
            print("Got unparseable packet. Trying again")
            (hdr, pkt) = capfile.next()
        while hdr is not None:
            # we should only be getting TCP, UDP, or ICMP/ICMPv6 records now, so parse accordingly
            handled = captureutils.handle_packet_parsing(pkt, hdr, utils)
            try:
                (hdr, pkt) = capfile.next()
            except:
                print("Got unparseable packet. Trying again")
                (hdr, pkt) = capfile.next()

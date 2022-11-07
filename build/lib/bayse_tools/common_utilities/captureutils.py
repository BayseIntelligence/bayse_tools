"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains functions that support capturing exactly what we need and nothing more.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""
import os
import pcapy
import subprocess
import time
from filelock import SoftFileLock, Timeout
from bayse_tools.common_utilities import packet
from bayse_tools.common_utilities import dnsutils


def create_bpf():
    """This function creates the Berkeley Packet Filter (BPF) capture filter to restrict us from capturing (and
       therefore wasting resources on) types of traffic that are not supported by Bayse. The steps are outlined
       below. TODO: Handle this traffic too!
    """


    """1. Create a valid BPF snippet to exclude all local protocols (those that communicate only on internal networks,
          or that have sensitive-but-uninteresting [to us] data when communicated externally).
    """
    local_protocols="445 or 5355 or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or 1900"

    """2. Create a BPF snippet that confirms that at least one IP address in EVERY conversation is NOT local (still
          only works for IPv4).
    """
    local_to_local_sans_dns="(src net 0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8) and (dst net (0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8)) and not port domain"

    """3. Assemble the full BPF that (in English) does the following:
          MUST be IP and no SMB or any other E-W protocols and no non-DNS local-to-local traffic and no IPv6 (since we
          do not handle IPv6 today).
    """
    bpf_to_apply = "tcp or udp or icmp or icmp6 or ip or ip6"
    #bpf_to_apply = "ip and not ip6" # filter out IPv6 (for now) only
    #bpf_to_apply="ip and ((not port (" + local_protocols + ")) and not (" + local_to_local_sans_dns + ") and not ip6)"
    return bpf_to_apply


def capture(**kwargs):
    """This function takes an interface to capture on and a BPF capture filter and begins capturing as requested.
       Because we work with flow data collected from the IP and Transport layers, we capture a much smaller amount
       of each packet to speed up processing and stay in-memory storage efficient.
    """
    utils = kwargs["utils"]
    is_verbose = kwargs["is_verbose"]
    capture_length = 500 # capture just 500 bytes from each packet (some multi-answer DNS packets were being cut short @ 300 bytes)
    capture_handle = pcapy.open_live(kwargs["interface"], capture_length, 0, 1) # setting the timeout value to -1 is unpredictable, and 0 is waiting forever.
    capture_handle.setfilter(kwargs["bpf"])

    # get the next packet and store it in our buffer
    while not utils.stop_thread:
        (hdr, pkt) = capture_handle.next()
        while hdr is not None and not utils.stop_thread:
            utils.packet_buffer.append((hdr, pkt))
            (hdr, pkt) = capture_handle.next()
    return


def handle_packet_parsing(pkt, hdr, utils, first=False):
    """Handles actual packet parsing, whether the packet is from a file or a live packet buffer.
    """
    pkt_len = len(pkt)
    success = True
    if pkt_len <= 34:  # length of IPv4 packet with standard header
        print(f"Warning: unexpectedly short packet:\n{pkt}")
    else:  # maybe legit IPv4 or IPv6 packet
        if utils.is_streaming and first:  # collect timing information
            utils.file_start_time = min(utils.file_start_time, utils.get_timestamp_from_packet_header(hdr))
            first = False  # reset it
        packet_info = packet.PacketInfo(pkt, hdr, utils)  # prep everything for later use
        if packet_info is None:
            print(f"Unparseable packet received. Skipping packet.")
            return False
        can_handle = (
                (packet_info.is_ipv4_by_ip_layer and packet_info.transport_protocol in [6, 17, 1])
                or (packet_info.is_ipv6_by_ip_layer and packet_info.transport_protocol in [6, 17, 58])
        )
        if not can_handle:
            if pkt[0] == 0 and pkt[4:6] == b"\x00\x06" and pkt[14:16] == b"\x08\x00":
                # this packet has a Linux-cooked header, so ignore first 2 bytes
                packet_info = packet.PacketInfo(pkt[2:], hdr, utils)  # prep everything for later use
                can_handle = True
        if not can_handle:  # error cases
            if packet_info.is_ipv4_by_ip_layer and packet_info.transport_protocol not in [6, 17, 1]:  # TCP, UDP, ICMP
                print(f"Warning, expected UDP, TCP, or ICMP but got {packet_info.transport_protocol} instead")
                return False
            elif packet_info.is_ipv6_by_ip_layer and packet_info.transport_protocol not in [6, 17, 58]:  # TCP, UDP, ICMPv6
                print(f"Warning, expected UDP, TCP, or ICMPv6 but got {packet_info.transport_protocol} instead")
                return False
            else:
                print("Warning, either something went wrong or this is not an IPv4 or IPv6 packet (handling for which "
                      "is unimplemented)")
                return False
        if packet_info.protocol_information in ["ICMP"]:  # handle protocols w/o layer 4 information specially
            ip_a_string = f"{packet_info.source_ip}:{packet_info.protocol_information}"
            ip_b_string = f"{packet_info.dest_ip}:{packet_info.protocol_information}"
        else:
            ip_a_string = f"{packet_info.source_ip}:{packet_info.source_port}"
            ip_b_string = f"{packet_info.dest_ip}:{packet_info.dest_port}"
        possible_key = f"{ip_a_string}-{ip_b_string}"
        possible_reverse_key = f"{ip_b_string}-{ip_a_string}"

        """Figure out if we've seen either side of the connection already. If we have, we just update the
           existing BayseFlow.
        """
        if packet_info.protocol_information in ["ICMP"]:
            if possible_key in utils.bayseflows.keys():
                bayseflow = utils.bayseflows[possible_key]
            elif possible_reverse_key in utils.bayseflows.keys():
                bayseflow = utils.bayseflows[possible_reverse_key]
            else:
                bayseflow = packet_info.determine_session_directionality(hdr)
        elif possible_key in utils.bayseflows.keys():
            bayseflow = utils.bayseflows[possible_key]
        elif possible_reverse_key in utils.bayseflows.keys():
            bayseflow = utils.bayseflows[possible_reverse_key]
        else:  # we don't yet know, so go figure it out!
            bayseflow = packet_info.determine_session_directionality(hdr)
            if bayseflow is None:  # somehow we didn't create a valid BayseFlow
                return False
        if bayseflow.key == possible_key:  # we're dealing with the source
            bayseflow.source_pkts += 1
            bayseflow.source_payload_bytes += packet_info.upper_layer_length  # payloadLength
            bayseflow.max_ts = max(bayseflow.max_ts, packet_info.packet_start_time)
        elif bayseflow.key == possible_reverse_key:  # we're dealing with the destination
            bayseflow.dest_pkts += 1
            bayseflow.dest_payload_bytes += packet_info.upper_layer_length  # payloadLength
            bayseflow.max_ts = max(bayseflow.max_ts, packet_info.packet_start_time)
        elif packet_info.protocol_information in ["ICMP"]:
            if bayseflow.key == possible_key:
                bayseflow.source_pkts += 1
                bayseflow.source_payload_bytes += packet_info.upper_layer_length  # payloadLength
                bayseflow.max_ts = max(bayseflow.max_ts, packet_info.packet_start_time)
            elif bayseflow.key == possible_reverse_key:
                bayseflow.dest_pkts += 1
                bayseflow.dest_payload_bytes += packet_info.upper_layer_length  # payloadLength
                bayseflow.max_ts = max(bayseflow.max_ts, packet_info.packet_start_time)
            else:
                print("Warning, protocol without upper layer info, but seems to be deformed!")
                return False
        else:
            print("Warning, deformed UDP or TCP object suspected!")
            return False
    return success


def process_packets(**kwargs):
    """Processes our accumulating packet buffer in a FIFO manner. Assigns each packet to the proper BayseFlow.
    """
    utils = kwargs["utils"]
    is_verbose = kwargs["is_verbose"]
    first = True  # we need to collect timestamp information on the first packet
    dnshelper = dnsutils.DNS(utils)  # create an instance of the DNS class to use
    while not utils.stop_thread:
        if len(utils.packet_buffer) > 0:
            packet_data = utils.packet_buffer.popleft()  # get the first (hdr, pkt) item -- process in FIFO order
            hdr = packet_data[0]
            pkt = packet_data[1]
            handled = handle_packet_parsing(pkt, hdr, utils, first)
        else:
            time.sleep(1)  # sleep for a second
            continue
    if utils.stop_thread:
        utils.set_bayseflow_durations()
        utils.set_stream_ids_for_pcap()
        dnshelper.get_passive_dns()
        """At this point, we want to see what existing passive DNS information was learned in recent sessions and use
           that first. TO do so, we need to lock the resource associated with the short-term pDNS file so that we don't
           make cleanup modifications to it while editing.
        """
        lock = SoftFileLock(dnshelper.short_term_passive_dns_lock_name)
        try:
            with lock.acquire(timeout=10):
                dnshelper.map_destination_ips_to_names()
                dnshelper.update_passive_dns_repository()  # add current file's DNS to the local PDNS file
        except Timeout:
            print("Lock acquisition for cleaning up short-term passive DNS took too long. Something might be wrong.")


def save_bayseflows(**kwargs):
    """This function saves the accumulated BayseFlows (from a streaming invocation of this functionality) to a .bf
       file. If the caller has requested that the BayseFlows be labeled, this will attempt to do so.
    """
    utils = kwargs["utils"]
    capture_thread = kwargs["capture_thread"]
    processing_thread = kwargs["processing_thread"]
    is_verbose = kwargs["is_verbose"]
    api_key = kwargs["key"]
    env_var = kwargs["environment_variable"]
    should_label = kwargs["should_label"]
    labeling_path = kwargs["labeling_path"]

    # stop active threads
    utils.stop_thread = True
    processing_thread.join()
    capture_thread.join(3)  # we need this to terminate after a few seconds if it's stuck waiting on no packets
    uuid = utils.get_random_uuid()
    utils.set_hash_value_for_sample(uuid)

    """Capture BayseFlows in JSON format, and store with all information for final transmission
    """
    utils.prepare_final_output_file()

    # check if output file looks sane
    utils.check_output_sanity()

    if should_label:
        api_key = api_key if api_key else os.environ.get(env_var)
        # construct the path to the labeling executable
        labeling_binary = f"{labeling_path}/" \
                          f"{utils.labeling_binary_name}" if labeling_path else utils.labeling_binary_name
        result = subprocess.run([labeling_binary, "-k", api_key, "--files", utils.bayseflow_output_filepath],
                                capture_output=True, text=True)
        if result.stdout:
            print(f"Details: {result.stdout}")
        if result.stderr:
            print(result.stderr)
            print("Labeling unsuccessful")
    #print("Conversion complete! Final BayseFlow Output stored at", utils.bayseflow_output_filepath)
    utils.cleanup_files()

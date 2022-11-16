"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains the BayseFlow class, which is used to capture the appropriate fields needed to create a
    BayseFlow object.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import copy
import sys
from bayse_tools.common_utilities import iputils


class BayseFlow:
    def __init__(self, s_ip, s_port, d_ip, d_port, timing_info, file_start_time, protocol_information, identifier=""):
        if protocol_information in ["ICMP"]:
            self.key = f"{s_ip}:{protocol_information}-{d_ip}:{protocol_information}"
        else:
            self.key = f"{s_ip}:{s_port}-{d_ip}:{d_port}"
        self.source_ip = s_ip
        self.source_port = s_port
        self.dest_port = d_port
        self.dest_ip = d_ip
        self.dest_name = ""  # where we'll store what we've learned the name to be
        self.min_ts = 0  # real value calculated in function at end
        self.max_ts = 0
        self.source_pkts = 0
        self.dest_pkts = 0
        self.source_payload_bytes = 0
        self.dest_payload_bytes = 0
        self.absolute_start_time = 0  # useful for figuring out which DNS name to use later (real value calculated in function at end)
        self.relative_start_time = 0  # how long after the file started did this session begin, rounded to 6 decimals
        self.duration = -1  # we can't know this until the end of session
        self.protocol_information = protocol_information # essentially should be empty unless it's ICMP right now
        self.identifier = identifier  # field to indicate how to tie this flow back to its (possible) source data
        self.calculate_timing_information(timing_info
                                        , file_start_time)  # we do this just once at the beginning, since these values are based on the start times

    def calculate_timing_information(self, timing_info, file_start_time):
        """Handles the fact that Packet-based BayseFlows will have a packet_header object with timing information, while
            Zeek-based flows will not. Populates min_ts, absolute_start_time, and relative_start_time fields.
        """

        if str(type(timing_info)) == "<class 'Pkthdr'>":
            ts_val = float(str(timing_info.getts()[0]) + "." + str(timing_info.getts()[1]).zfill(6))
            self.min_ts = ts_val
            self.absolute_start_time = ts_val
            self.relative_start_time = float("%.6f" % (ts_val - file_start_time))
        elif isinstance(timing_info, float):  # Zeek data should hit this case.
            self.min_ts = timing_info
            self.absolute_start_time = timing_info
            self.relative_start_time = float("%.6f" % (timing_info - file_start_time))
        else:
            print("Unrecognized instance passed in. Type:", type(timing_info))
            sys.exit(1)

    def set_bayseflow_duration(self):
        """Uses stored information to figure out how long this BayseFlow lasted.
        """
        self.duration = float("%.6f" % (self.max_ts - self.min_ts))

    def is_correct_direction(self):
        """This is derived from the code found in packet.py, but useful for other formats (TODO: Move
        packet.py's functionality here too?). Determines if the BayseFlow is most likely correct in which side is
        labeled as the source and which side is labeled as the destination. This is only useful for inputs where
        there is not necessarily directionality provided. Incoming data will be BayseFlows.

        Even though the information in the initial BayseFlows will be labeled source and dest, we don't actually know
        which is the source/dest for the entire session.

        The directionality logic comes from knowledge of relevant RFCs plus experience with common session behavior
        on the Internet.
        """
        is_correct_direction = True
        if iputils.check_if_local_ip(str(self.source_ip)):
            if self.source_port == "" and self.protocol_information in ["ICMP"]:
                """ICMP is treated specially, since it doesn't have a port number...so we need to save the whole
                   source/dest IP pair in addition to the protocol information. Additionally, we already know that the
                   source IP of this packet is local, so we'll set it as the source
                """
                # Keep as-is, instead of flipping
                return is_correct_direction
            if int(self.source_port) > 49151:
                """Source IP is local and has an ephemeral port, so create a new bayseflow object, store it in our
                    BayseFlows dictionary, and return it.
                """
                # Keep as-is, instead of flipping
                return is_correct_direction
            else:
                """The source IP of this packet is local AND has well-known or registered port, and the destination IP
                    of this packet is NOT LOCAL (we know for sure via check in line # 75 above). So now try to figure 
                    out if this is actually the first packet of an internal-to-external session, or if we're seeing an
                    in-progress external-to-internal session. This analysis will necessarily have to be done based on
                    port numbers and is fallible.
                """
                if int(self.dest_port) > 49151:
                    """Destination IP of this packet is NOT local and has ephemeral port, so it's likely the source of 
                        an external-to-internal session.
                    """
                    # Flip this one
                    is_correct_direction = False
                    return is_correct_direction
                """Here we already know that this packet's source IP is local, the dest IP is not local, the source
                   port is not ephemeral, and the dest port is not ephemeral...so now we should determine if the
                   destination's port is well-known. If it is, then it's more than likely the destination. If it's not, 
                   then we should default to making the local IP (AKA the source IP of this packet) the source.
                """
                if int(self.dest_port) < 1024:
                    return is_correct_direction
                else:
                    """Both have ephemeral ports, and we see this packet first. The source of this packet has a local
                        source IP and a non-local destination IP. So whichever port is lower should be the destination.
                        IF both ports are the same, the source of this packet should be the session source (since we 
                        have no way of knowing better).
                    """
                    if int(self.dest_port) > int(self.source_port):
                        is_correct_direction = False
                        return is_correct_direction
                    else:
                        # Keep as-is, instead of flipping
                        return is_correct_direction
        else:  # first IP is not a local IP, so check the second IP in the line
            """ICMP is treated specially, since it doesn't have a port number...so we need to save the whole
               source/dest IP pair in addition to the protocol information.
            """
            if self.dest_port == "" and self.protocol_information in ["ICMP"]:
                if not iputils.check_if_local_ip(str(self.dest_ip)):
                    """Neither IP for this packet is local, and we saw this packet first, so we'll set it as the source.
                    """
                    # Keep as-is, instead of flipping
                    return is_correct_direction
                else:
                    # Flip this one
                    is_correct_direction = False
                    return is_correct_direction
            """Source IP is NOT a local IP. So at this point, the first packet we see in the session could either be
                external-to-internal OR we're capturing a packet from the destination of an in-progress session. To 
                determine which side is treated as the actual flow source, we'll do the following:
                1. If the Destination of this packet is also NOT a local IP AND both Source and Destination ports are 
                   above the well-known port range (0-1023), we'll identify this packet as the flow Source since we saw
                   it first.
                2. If both of the conditions above don't hold true, simply look at the port numbers. If the source port 
                of this packet is greater than the destination, we'll treat it as the flow source. If the source and 
                destination ports are identical, we'll again treat this as the flow source (since this may actually 
                be the first packet in a session). Finally, if the destination port of this packet is greater than 
                the source, we'll treat the destination as the flow's source (since we have no way of knowing better).
             """
            if not iputils.check_if_local_ip(str(self.dest_ip)) and int(self.dest_port) > 1023 and int(
                    self.source_port) > 1023:
                """Neither IP for this packet is local, and we saw this packet first, so we'll set it as the source.
                """
                # Keep as-is, instead of flipping
                return is_correct_direction
            if int(self.dest_port) > int(self.source_port):
                # Flip this one
                # dest port is higher, so it's treated as the source
                is_correct_direction = False
                return is_correct_direction
            else:
                # Keep as-is, instead of flipping
                # both ports are the same OR the source is higher, so source of this packet treated as the source
                return is_correct_direction

    def flip_bayseflow_order(self):
        """The order of this BayseFlow seems to be wrong, so we need to flip all of the fields that deal with
           directionality. Note that this should always be called before naming occurs.
        """
        orig_bayseflow = copy.deepcopy(self)
        if self.protocol_information != "ICMP":
            self.key = f"{orig_bayseflow.dest_ip}:{orig_bayseflow.dest_port}-" \
                                 f"{orig_bayseflow.source_ip}:{orig_bayseflow.source_port}"
        else:
            self.key = f"{orig_bayseflow.dest_ip}:{self.protocol_information}-" \
                                 f"{orig_bayseflow.source_ip}:{self.protocol_information}"
        self.source_ip = orig_bayseflow.dest_ip
        self.source_port = orig_bayseflow.dest_port
        self.dest_port = orig_bayseflow.source_port
        self.dest_ip = orig_bayseflow.source_ip
        self.source_pkts = orig_bayseflow.dest_pkts
        self.dest_pkts = orig_bayseflow.source_pkts
        self.source_payload_bytes = orig_bayseflow.dest_payload_bytes
        self.dest_payload_bytes = orig_bayseflow.source_payload_bytes

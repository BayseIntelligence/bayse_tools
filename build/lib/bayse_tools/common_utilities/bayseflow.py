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

import sys


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


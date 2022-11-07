"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains utility functions and variables that are used by a number of callers.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import collections
import json
import os
import sys
import uuid
from pathlib import Path


class Utilities:
    NEXT_TCP_STREAM_VALUE = 0  # useful for tying BayseFlows from PCAPs back to tcp.stream value
    NEXT_UDP_STREAM_VALUE = 0  # useful for tying BayseFlows from PCAPs back to udp.stream value
    local_ips_forward_regex = r"^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\."
    local_ips_reverse_regex = r"([0-9]{1,3})\.([0-9]{1,3})\.((1[6-9]\.172)|(2[0-9]\.172)|(3[0-1]\.172)|([0-9]{1,3}\.10)|(168\.192))\.in\-addr\.arpa\.$"
    ipv6_regex = r"(([1-9a-fA-F]{1,}:)"  # very basic, meant to filter out virtually anything right now. Also not currently used

    def __init__(self, orig_fp, platform_type, output_dir=None, sample_type=None):
        self.active_external_ips = set()
        self.questions = dict()
        self.original_filepath = orig_fp
        if orig_fp is None:
            self.is_streaming = True
        else:
            self.is_streaming = False
        self.output_dir = output_dir  # optional place to store the finished file
        self.system_type = platform_type
        self.filtered_filepath = ""
        self.bayseflows = collections.OrderedDict()  # dict of BayseFlow objects (TCP, UDP, or ICMP)
        self.file_start_time = float(99999999999)  # set it impossibly high at beginning
        self.tmp_filepath = ""  # file to temporarily store just the bayseflows with proper formatting. Needed in order to have a consistent file to hash
        self.bayseflow_output_filepath = ""  # file to store the final output intended to be sent back to the caller
        self.sample_name = ""
        self.sample_type = sample_type  # track the type of sample we're processing (Zeek, Interflow, PCAP, etc...)
        self.bayseflows_hash = ""  # used to store the hash of the bayseflows file
        """ Generic flows are flow objects that are partially-converted from their myriad original formats (such as Zeek
            conn.log flows, Stellar Cyber Interflow flows, and so on) into the BayseFlow format. However, they are not yet
            actually meaningful BayseFlows. So this interim generic state allows us to reuse code that needs to happen
            across all of these various input flow types while keeping any necessary input-specific logic in the various
            input-specific Python classes.
        """
        self.genericflows = collections.OrderedDict()
        self.file_format = None  # track format of data passed in
        self.packet_buffer = collections.deque() #create an empty buffer to store packets that have not yet been processed
        self.stop_thread = False #keep state of whether thread should be stopped
        self.labeling_binary_name = "labeling"  # stores the name of the labeling binary in case labeling is desired

    def cleanup_files(self):
        """Removes any files that were created in the interim but not needed for the final output.
        """
        if not self.genericflows:  # we were working with PCAP data
            # delete the filtered file, if it exists
            try:
                os.remove(self.filtered_filepath)
            except OSError:
                print("Failed to find and delete filtered file.")
                pass
        # delete the temporary file, if it exists
        try:
            os.remove(self.tmp_filepath)
        except OSError:
            pass
        # TODO: Handle streaming cleanup elsewhere
        #if self.is_streaming or len(self.bayseflows) == 0: # only delete if streaming or empty
        #    # delete the final output .bf file, if it exists
        #    try:
        #        os.remove(self.bayseflow_output_filepath)
        #    except OSError:
        #        pass

    def get_timestamp_from_packet_header(self, packet_header):
        """Simple utility to transform packet_header's startTime into a usable float value.
        """
        return float(str(packet_header.getts()[0]) + "." + str(packet_header.getts()[1]).zfill(6))

    def set_bayseflow_durations(self):
        """Iterates through all bayseflows and updates their flow duration fields.
        """
        for bayseflow in self.bayseflows:
            self.bayseflows[bayseflow].set_bayseflow_duration()

    def set_stream_ids_for_pcap(self):
        """PCAP-like formats have a nice helper functionality (in Wireshark, tcpdump, etc...) that tell you which
           TCP or UDP stream (0 is the first) a packet belongs to, which allows people to easily filter on particular
           streams. Since this functionality isn't actually part of a packet but is rather a higher-level construct,
           we need to recreate it by identifying which TCP or UDP stream a BayseFlow corresponds to.
        """
        # first, make sure we're in ascending relativeStart order
        self.bayseflows = {k: v for k, v in sorted(self.bayseflows.items(),
                                                   key=lambda item: item[1].relative_start_time)}

        for bayseflow in self.bayseflows:
            if self.bayseflows[bayseflow].protocol_information.upper() == "TCP" and self.bayseflows[
                bayseflow].identifier == "":
                self.bayseflows[bayseflow].identifier = f"{self.NEXT_TCP_STREAM_VALUE}"
                self.NEXT_TCP_STREAM_VALUE += 1
            elif self.bayseflows[bayseflow].protocol_information.upper() == "UDP" and self.bayseflows[
                bayseflow].identifier == "":
                self.bayseflows[bayseflow].identifier = f"{self.NEXT_UDP_STREAM_VALUE}"
                self.NEXT_UDP_STREAM_VALUE += 1


    def save_bayseflows_to_file(self):
        """Saves BayseFlows to a .bf file for hashing.
        """
        # get the proper file name
        last_dot = self.filtered_filepath.rfind(".")
        if last_dot == -1:  # no extension in file name
            self.tmp_filepath = self.filtered_filepath + ".tmp"
        else:
            self.tmp_filepath = self.filtered_filepath[:last_dot] + ".tmp"
        with open(self.tmp_filepath, "w") as sf_out:
            for bayseflow in self.bayseflows.keys():
                if self.bayseflows[bayseflow].protocol_information in ["ICMP"]:
                    sf_out.write(f"{self.bayseflows[bayseflow].source_ip}"
                                 f" <-> "
                                 f"{self.bayseflows[bayseflow].dest_name}"
                                 f"\t{self.bayseflows[bayseflow].source_pkts}"
                                 f"\t{self.bayseflows[bayseflow].source_payload_bytes}"
                                 f"\t{self.bayseflows[bayseflow].dest_pkts}"
                                 f"\t{self.bayseflows[bayseflow].dest_payload_bytes}"
                                 f"\t{self.bayseflows[bayseflow].relative_start_time}"
                                 f"\t{self.bayseflows[bayseflow].protocol_information}"
                                 f"\t{self.bayseflows[bayseflow].identifier}"
                                 f"\t{self.bayseflows[bayseflow].duration}"
                                 f"\n"
                                )
                else:
                    sf_out.write(f"{self.bayseflows[bayseflow].source_ip}:{self.bayseflows[bayseflow].source_port}"
                                 f" <-> "
                                 f"{self.bayseflows[bayseflow].dest_name}:{self.bayseflows[bayseflow].dest_port}"
                                 f"\t{self.bayseflows[bayseflow].source_pkts}"
                                 f"\t{self.bayseflows[bayseflow].source_payload_bytes}"
                                 f"\t{self.bayseflows[bayseflow].dest_pkts}"
                                 f"\t{self.bayseflows[bayseflow].dest_payload_bytes}"
                                 f"\t{self.bayseflows[bayseflow].relative_start_time}"
                                 f"\t{self.bayseflows[bayseflow].protocol_information}"
                                 f"\t{self.bayseflows[bayseflow].identifier}"
                                 f"\t{self.bayseflows[bayseflow].duration}"
                                 f"\n"
                                )

    def get_random_uuid(self) -> object:
        """Assigns a random uuid to the sample file
        """
        return str(uuid.uuid4()).replace("-", "")

    def set_hash_value_for_sample(self, uuid):
        """Assigns a uuid to the sample file
        """
        self.bayseflows_hash = uuid

    def prepare_final_output_file(self):
        """Captures BayseFlows and other important metadata in JSON format for final transmission back to the caller
            (usually an API).
        """
        if self.is_streaming: # this is streaming mode
            time_str = str(self.file_start_time)
            start_time_str = str(time_str[:time_str.find(".")])
            self.bayseflow_output_filepath = f"{self.system_type}_{start_time_str}.bf"
        else:
            if not self.is_streaming and not Path(self.tmp_filepath).is_file():
                print(f"Warning: temporary file path ({self.tmp_filepath}) does not exist. Aborting.")
                sys.exit(1)
            else:
                # get the proper file name
                last_dot = self.filtered_filepath.rfind(".")
                if last_dot == -1:  # no extension in file name
                    self.bayseflow_output_filepath = self.filtered_filepath + ".bf"
                else:
                    self.bayseflow_output_filepath = self.filtered_filepath[:last_dot] + ".bf"

        """Use the dictionary version of this file to convert it (plus some other information) to JSON
        """
        # first, make sure we're in ascending relativeStart order
        self.bayseflows = {k: v for k, v in sorted(self.bayseflows.items(), key=lambda item: item[1].relative_start_time)}

        with open(self.bayseflow_output_filepath, "w") as bayseflow_outfile:
            self.sample_name = os.path.basename(self.bayseflow_output_filepath)
            rows = []
            for flow in self.bayseflows.keys():
                if self.bayseflows[flow].protocol_information in ["ICMP"]:
                    #first_delimiter = self.bayseflows[flow].key.find(":")
                    rows += [
                                {"src": self.bayseflows[flow].source_ip,
                                 "dst": self.bayseflows[flow].dest_name,
                                 "destinationNameSource": self.bayseflows[flow].destination_name_source,
                                 "srcPkts": self.bayseflows[flow].source_pkts,
                                 "srcBytes": self.bayseflows[flow].source_payload_bytes,
                                 "dstPkts": self.bayseflows[flow].dest_pkts,
                                 "dstBytes": self.bayseflows[flow].dest_payload_bytes,
                                 "relativeStart": self.bayseflows[flow].relative_start_time,
                                 "protocolInformation": self.bayseflows[flow].protocol_information,
                                 "identifier": self.bayseflows[flow].identifier,
                                 "duration": self.bayseflows[flow].duration
                                }
                            ]
                else:
                    rows += [
                                {"src": f"{self.bayseflows[flow].source_ip}:{self.bayseflows[flow].source_port}",
                                 "dst": f"{self.bayseflows[flow].dest_name}:{self.bayseflows[flow].dest_port}",
                                 "destinationNameSource": self.bayseflows[flow].destination_name_source,
                                 "srcPkts": self.bayseflows[flow].source_pkts,
                                 "srcBytes": self.bayseflows[flow].source_payload_bytes,
                                 "dstPkts": self.bayseflows[flow].dest_pkts,
                                 "dstBytes": self.bayseflows[flow].dest_payload_bytes,
                                 "relativeStart": self.bayseflows[flow].relative_start_time,
                                 "protocolInformation": self.bayseflows[flow].protocol_information,
                                 "identifier": self.bayseflows[flow].identifier,
                                 "duration": self.bayseflows[flow].duration
                                }
                            ]
            # metadata for the file that is important to keep track of
            bayseflow_output = {"hash": self.bayseflows_hash, "trafficDate": str(self.file_start_time),
                          "fileName": self.sample_name,
                          "BayseFlows": rows}
            json.dump(bayseflow_output, bayseflow_outfile)
            return self.bayseflow_output_filepath

    def check_output_sanity(self):
        """Determines if there are any issues with the final output file. Issues could include:
                1. having no resulting BayseFlows (this is atypical but not an error in this case)
                2. having a default time (meaning that we didn't process anything)
        """
        try:
            with open(self.bayseflow_output_filepath, "r") as bayseflow_outfile:
                out_file = json.load(bayseflow_outfile)
                if out_file["trafficDate"] == "99999999999.0":  # default date value
                    if len(out_file["BayseFlows"]) == 0:
                        print("No BayseFlows found in file. Bayse currently handles only IPv4 to or from the "
                              "Internet. Nothing to do."
                              )
                        return
                    else:
                        print("Error: File seems to have BayseFlows, but date of traffic wasn't correctly "
                              "learned. Aborting."
                              )
                        sys.exit(1)
        except:
            print("Something went wrong while trying to check output file for sanity. Aborting.")
            self.cleanup_files()
            sys.exit(1)

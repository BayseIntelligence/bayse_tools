"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains utilities that perform actions on flows of various types after they have been partially parsed.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import re
import sys
import magic
from bayse_tools.common_utilities import iputils


def remove_local_traffic_from_generic_flows(utils):
    """Removes the local traffic from the incoming dictionary of genericflows.
    """
    tmp_dict = dict()
    for flow_group in utils.genericflows.keys():
        tmp_flowlist = []  # clear it each time through the group
        for flow in utils.genericflows[flow_group]:
            if iputils.check_if_local_ip(flow.source_ip) and iputils.check_if_local_ip(flow.dest_ip):
                # print("removing", flow.source_ip, "<->", flow.dest_ip, "from flows dictionary.")
                continue
            else:  # one of the sides is not local
                tmp_flowlist += [flow]
        tmp_dict[flow_group] = tmp_flowlist  # keep only the ones that aren't local-to-local
    utils.genericflows = tmp_dict


def identify_earliest_flow_start_time(utils):
    """Takes a genericflows dictionary and finds the earliest start time.
    """
    ts = float(99999999999)
    for flow_group in utils.genericflows.keys():
        for flow in utils.genericflows[flow_group]:
            ts = min(ts, float(flow.timestamp))
    utils.file_start_time = ts


def validate_file_format(utils):
    """Validate if file is of various file types -- very weak check for correct
       data, unfortunately.
    """
    valid = True
    utils.file_format = magic.from_file(utils.original_filepath)
    if utils.sample_type == "Zeek":
        if not re.match(r"^(ASCII text|JSON (text |)data|New Line Delimited "
                        r"JSON text data)$", utils.file_format):
            valid = False
    elif utils.sample_type == "Interflow":
        if not re.match(r"^JSON (text |)data|New Line Delimited JSON text data$"
                        , utils.file_format):
            valid = False
    else:
        valid = False
    if not valid:
        print(f"Error: {utils.original_filepath}, of type {utils.file_format} "
              f"is not an accepted file type for {utils.sample_type}.")
        sys.exit(1)

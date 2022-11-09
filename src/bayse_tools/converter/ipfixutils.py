"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 11/08/2022

    This file contains utilities that allow a Cisco Netflow (and an optional dns) log to be converted into
    equivalent BayseFlows.

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import json
from bayse_tools.common_utilities import iputils
from bayse_tools.common_utilities import bayseflow
from bayse_tools.converter import generic_flowutils
from bayse_tools.converter import netflow_v9 as netflow


def store_netflows(utils):
    """Takes a JSON file of Netflow records (either one JSON record per line or a list of JSON records separated by
       commas) and stores the fields that we need from the input as a dictionary. Each record is stored as a genericflow
       object with each object accessible by the key used for BayseFlows.
    """
    is_json = True if utils.file_format is not None and "JSON" in \
                      utils.file_format else False
    with open(utils.original_filepath) as infile:
        if is_json:
            flows = []
            for line in infile:
                data = json.loads(line)
                if type(data) == list:
                    # list of flows, so capture them all
                    flows = data
                elif type(data) == dict:
                    flows += [data]
                else:
                    print(f"Unrecognized JSON data {type(data)}")
                    return None
        else:
            print("Expected JSON but did not get it. Quitting.")
            return None
        for flowdata in flows:
            netflow_object = netflow.Netflow(flowdata, is_json)
            if netflow_object.bayseflow_key is None:
                print("Failed to capture key for Netflow object; skipping record. Please see errors before this!")
                continue
            if netflow_object.bayseflow_key not in utils.genericflows.keys():
                utils.genericflows[netflow_object.bayseflow_key] = []
            utils.genericflows[netflow_object.bayseflow_key] += [(netflow_object)]


def convert_netflow_to_bayseflow(utils):
    """This function takes the original Netflow objects (stored as genericflows) and converts them into BayseFlows.
       BayseFlows are made up of one Netflow record...
    """

    for flow_group in utils.genericflows.keys():
        # sort the flows in a flow group by their start timestamp
        utils.genericflows[flow_group] = sorted(utils.genericflows[flow_group], key=lambda x: x.timestamp)

        bayseflow_object = None  # start off empty

        for netflow in utils.genericflows[flow_group]:
            if netflow.bayseflow_key not in utils.bayseflows.keys():  # we've not collected this sourceIP:source_port
                bayseflow_object = bayseflow.BayseFlow(netflow.source_ip
                                                , netflow.source_port
                                                , netflow.dest_ip
                                                , netflow.dest_port
                                                , float(netflow.timestamp)
                                                , float(utils.file_start_time)
                                                , netflow.protocol_information
                                                )  # create a new BayseFlow object
                utils.bayseflows[netflow.bayseflow_key] = bayseflow_object  # store it

            # collect packet info from netflow
            bayseflow_object.source_pkts += int(netflow.source_pkts)
            bayseflow_object.dest_pkts += int(netflow.dest_pkts)

            # collect byte info from netflow, if it exists
            try:
                bayseflow_object.source_payload_bytes += int(netflow.source_bytes)
            except:
                pass  # it's legitimately possible that source bytes is "-"
            try:
                bayseflow_object.dest_payload_bytes += int(netflow.dest_bytes)
            except:
                pass  # it's legitimately possible that dest bytes is "-"

            # get the max duration of the flow
            if netflow.duration != "-":
                bayseflow_object.max_ts = max(bayseflow_object.max_ts, netflow.timestamp + float(netflow.duration))
            else:
                bayseflow_object.max_ts = max(bayseflow_object.max_ts, netflow.timestamp)
            # if the netflow has a name for the destination, capture it now
            if netflow.proposed_destname is not None:
                bayseflow_object.dest_name = netflow.proposed_destname
        if bayseflow_object is not None:
            bayseflow_object.set_bayseflow_duration()


def netflow_2_bayseflows(utils, dnshelper):
    """Given a JSON log file of netflow records that has been lightly validated, store the netflows, collect both
       local and public DNS lookups, and convert the remaining netflows to BayseFlows.
    """

    # store file as a dict for easier processing
    store_netflows(utils)

    # collect DNS records (both local and public lookups)
    dnshelper.collect_dns_records_from_netflow_sample()

    if len(utils.genericflows) == 0:
        print("No netflows were found in file. No traffic was converted to BayseFlows.")

    # get file start time
    generic_flowutils.identify_earliest_flow_start_time(utils)

    # convert from netflow to BayseFlow
    convert_netflow_to_bayseflow(utils)


def json_extract(obj, key, dict_expected=False):
    """Recursively fetch values from nested JSON. Code credit to Todd Birchard at
    https://hackersandslackers.com/extract-data-from-complex-json-python/. Slightly modified to handle dicts as end
    types.
    """
    arr = []
    def extract(obj, arr, key, dict_expected=False):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    if dict_expected and isinstance(v, dict):
                        arr.append(v)
                    else:
                        extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                if dict_expected and isinstance(item, dict):
                    arr.append(item)
                else:
                    extract(item, arr, key)
        return arr
    values = extract(obj, arr, key, dict_expected)
    return values
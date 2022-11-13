"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 11/08/2022

    This file contains utilities that allow a Cisco Netflow (and an optional dns) log to be converted into
    equivalent BayseFlows.

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
import ipaddress
import json
import re
from bayse_tools.common_utilities import iputils
from bayse_tools.common_utilities import bayseflow
from bayse_tools.converter import generic_flowutils
from bayse_tools.converter import netflow_v9 as netflow

HEADER_MAPS = {
    "absolute_start_time": ["date first seen", "date flow start", "ts"],
    "endtime": ["te"],
    "duration": ["duration", "td"],
    "protocolInformation": ["proto", "pr"],
    "sourcedata": ["src ip addr:port"],
    "src": ["sa"],
    "sourcepackets": ["packets", "ipkt"],
    "source_bytes_flows": ['bytes flows'],
    "srcport": ["sp"],
    "srcbytes": ["ibyt"],
    "destinationdata": ["dst ip addr:port"],
    "dst": ["da"],
    "dstbytes": ["obyt"],
    "dstport": ["dp"],
    "destinationpackets": ["opkt"],
    "direction": ["dir"]

}
"""^ What we should call fields and what they can possibly be in the various formats of Netflow. Short names from
 Appendix B of https://www.giac.org/paper/gcia/9290/netflow-collection-analysis-nfcapd-python-splunk/129719
"""


def store_netflows(utils):
    """Takes a Netflow file, removes the header lines, and stores the input as a dictionary. We store each line in the
       file as a generic flow, but then we store each flow object by the key used for BayseFlows. The fields that we
       need from the input are stored as a dictionary. Each record is stored as a genericflow object with each object
       accessible by the key used for BayseFlows.
    """
    is_json = True if utils.file_format is not None and "JSON" in utils.file_format else False
    with open(utils.original_filepath) as infile:
        numfields = -1
        if is_json:
            print(f"{utils.file_format} not currently supported.")
            return None
            # TODO: The JSON format from nfdump is garbage because it spits out a prettified JSON record,
            #  not actually valid JSON...
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
            for flowdata in flows:
                important_fields = dict()
                # an individual line, which actually doesn't generally capture all of the data for a 4-tuple.
                for field in flowdata:
                    for key in HEADER_MAPS:
                        if field.lower() in HEADER_MAPS[key]:
                            print(f"Found {field} in {HEADER_MAPS[key]}")
                            important_fields[key] = field
                print(f"Important fields: {important_fields}")
                netflow_object = netflow.Netflow(flowdata, is_json)
                if netflow_object.bayseflow_key is None:
                    print("Failed to capture key for Netflow object; skipping record. Please see errors before this!")
                    continue
                if netflow_object.bayseflow_key not in utils.genericflows.keys():
                    utils.genericflows[netflow_object.bayseflow_key] = []
                utils.genericflows[netflow_object.bayseflow_key] += [netflow_object]
        elif "CSV" in utils.file_format:
            important_fields = dict()  # we'll only collect the positioning of things we care about and ignore the rest
            important_flowdata = dict()  # where to store the data from the fields we care about
            for num, line in enumerate(infile):
                if len(line) == 0:
                    continue
                if re.match(r"^[a-zA-Z]", line[0]):  # we're expecting lines with data to start with some kind of tstamp
                    if num == 0:  # first line, probably has header info
                        print("Header data (raw):", line)
                        headerinfo = list(filter(None, re.split(",", line.lower().strip())))
                        print(f"Tokenized header data: {headerinfo}")
                        numfields = len(headerinfo)  # capture number of fields so we can ignore lines of diff length
                        for i, name in enumerate(headerinfo):
                            for key in HEADER_MAPS:
                                if name.strip() in HEADER_MAPS[key]:
                                    important_fields[key] = i
                        # TODO! Make the field collection function (so we can handle varied formats) separate!
                        print("After analyzing header, we have the following important fields in these positions:", important_fields)
                    continue  # skip other comment/header lines and ignore processing this line for data
                flowdata = list(filter(None, re.split(",", line.lower().strip())))
                # an individual line, which actually may not capture all of the data for a 4-tuple.
                if numfields != -1 and len(flowdata) != numfields:
                    print(f"Skipping line {flowdata} which seems not to match the file format for flow rows")
                    continue
                print(f"Tokenized flow data: {flowdata}")
                for num, field in enumerate(flowdata):
                    if num in important_fields.values():
                        field = field.strip()  # get rid of extraneous whitespace
                        field_name = list(important_fields.keys())[list(important_fields.values()).index(num)]
                        important_flowdata[field_name] = field
                print(f"After collecting what matters, here's what we have:", important_flowdata.items())
                # TODO: Start here, as this is actually a feasible path forward for meeting the upcoming timeline
                netflow_object = netflow.Netflow(important_flowdata)#, is_json)
                if netflow_object.bayseflow_key is None:
                    print("Failed to capture key for Netflow object; skipping record. Please see errors before this!")
                    continue
                print(f"Is {netflow_object.bayseflow_key} in {utils.genericflows.keys()}?")
                if netflow_object.bayseflow_key not in utils.genericflows.keys():
                    print(f"No! Is {netflow_object.reverse_key} ?")
                    if netflow_object.reverse_key not in utils.genericflows.keys():
                        utils.genericflows[netflow_object.bayseflow_key] = []
                    else:
                        print(f"Yes! So now we've flipped order!")
                        netflow_object.flip_netflow_order()  # this allows us to simplify code below
                utils.genericflows[netflow_object.bayseflow_key] += [netflow_object]
            return None  # temporary
        else:
            print("TODO.")
            """
            #TODO: Fix all of this, dependent on what format(s) we should expect.
            print(f"{utils.file_format} not currently supported.")
            return None
            # capture TSV format
            important_fields = dict()  # we'll only collect the positioning of things we care about and ignore the rest
            important_flowdata = dict()  # where to store the data from the fields we care about
            for num, line in enumerate(infile):
                if len(line) == 0:
                    continue
                if re.match(r"^[a-zA-Z]", line[0]):  # we're expecting lines with data to start with some kind of tstamp
                    if num == 0:  # first line, probably has header info
                        print("Header data (raw):", line)
                        headerinfo = list(filter(None, re.split("\t|  ", line.lower().strip())))  # handle both TSV and
                        # content separated by 2+ spaces
                        print(f"Tokenized header data: {headerinfo}")
                        for i, name in enumerate(headerinfo):
                            for key in HEADER_MAPS:
                                if name.strip() in HEADER_MAPS[key]:
                                    important_fields[key] = i
                        # TODO! Make the field collection function (so we can handle varied formats) separate!
                        print("After analyzing header, we have the following important fields in these positions:", important_fields)
                    continue  # skip other comment/header lines and ignore processing this line for data
                flowdata = list(filter(None, re.split("\t|  ", line.lower().strip())))
                # an individual line, which actually doesn't generally capture all of the data for a 4-tuple.
                print(f"Tokenized flow data: {flowdata}")
                for num, field in enumerate(flowdata):
                    if num in important_fields.values():
                        field = field.strip()  # get rid of extraneous whitespace
                        field_name = list(important_fields.keys())[list(important_fields.values()).index(num)]
                        important_flowdata[field_name] = field
                print(f"After collecting what matters, here's what we have:", important_flowdata.items())
                # TODO: Start here and keep mucking with stuff. Below is rough output of this right now, which shows
                #  issues:

                Tokenized header data: ['date first seen', ' duration', ' proto', 'src ip addr:port', 'dst ip addr:port', ' packets', 'bytes flows']
                After analyzing header, we have the following important fields in these positions: {'absolute_start_time': 0, 'duration': 1, 'protocolInformation': 2, 'sourcedata': 3, 'destinationdata': 4, 'sourcepackets': 5, 'source_bytes_flows': 6}
                Tokenized flow data: ['2022-02-15 21:23:52.441', ' 00:00:00.000 udp', ' 10.2.9.133:59889 ->', ' 10.2.9.9:53', ' 1', ' 51', ' 1']
                After collecting what matters, here's what we have: dict_items([('absolute_start_time', '2022-02-15 21:23:52.441'), ('duration', '00:00:00.000 udp'), ('protocolInformation', '10.2.9.133:59889 ->'), ('sourcedata', '10.2.9.9:53'), ('destinationdata', '1'), ('sourcepackets', '51'), ('source_bytes_flows', '1')])

                if num > 5:
                    return None  # temporary
                continue  # temporary to skip any actual processing
                netflow_object = netflow.Netflow(flowdata, is_json)
                if netflow_object.bayseflow_key is None:
                    print("Failed to capture key for Netflow object; skipping record. Please see errors before this!")
                    continue
                if netflow_object.bayseflow_key not in utils.genericflows.keys():
                    utils.genericflows[netflow_object.bayseflow_key] = []
                utils.genericflows[netflow_object.bayseflow_key] += [netflow_object]
            """


def convert_netflow_to_bayseflow(utils):
    """This function takes the original Netflow objects (stored as genericflows) and converts them into BayseFlows.
       BayseFlows are made up of one Netflow record...
    """
    ethernet_header_bytes = 14  # Netflow doesn't ignore header data, so we need to...
    ipv4_header_bytes = 20  # fixed size
    ipv6_header_bytes = 40  # fixed size
    udp_header_bytes = 8  # fixed size
    tcp_header_bytes = 20  # minimum header size
    icmpv4_header_bytes = 8  # fixed size
    icmpv6_header_bytes = 4  # header bytes extend past here, but always has 4 bytes of standard options

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
            # TODO: Any way for us to capture DNS naming?
            #if netflow.proposed_destname is not None:
            #    bayseflow_object.dest_name = netflow.proposed_destname
        if bayseflow_object is not None:
            # identify layer 3 type to find how many header bytes to ignore
            header_bytes_to_ignore = 0
            try:
                ipaddress.IPv4Address(netflow.source_ip)
                header_bytes_to_ignore = ipv4_header_bytes
                if netflow.protocol_information == "ICMP":
                    header_bytes_to_ignore += icmpv4_header_bytes
            except:
                try:
                    ipaddress.IPv6Address(netflow.source_ip)
                    header_bytes_to_ignore = ipv6_header_bytes
                    if netflow.protocol_information == "ICMP":
                        header_bytes_to_ignore += icmpv6_header_bytes
                except:
                    print(f"Error: {netflow.source_ip} is neither an IPv6 nor IPv6 address. Skipping.")
                    continue
            if netflow.protocol_information == "TCP":
                header_bytes_to_ignore += tcp_header_bytes
            elif netflow.protocol_information == "UDP":
                header_bytes_to_ignore += udp_header_bytes
            print(f"BEFORE MODS, Bayseflow object {bayseflow_object.key} has "
                  f"{bayseflow_object.source_pkts} source packets, {bayseflow_object.source_payload_bytes} source "
                  f"bytes, {bayseflow_object.dest_pkts} dest packets, {bayseflow_object.dest_payload_bytes} dest bytes"
                  f" for protocol {bayseflow_object.protocol_information}")
            bayseflow_object.source_payload_bytes -= (bayseflow_object.source_pkts * header_bytes_to_ignore)
            bayseflow_object.dest_payload_bytes -= (bayseflow_object.dest_pkts * header_bytes_to_ignore)
            print(f"AFTER MODS, Bayseflow object {bayseflow_object.key} has "
                  f"{bayseflow_object.source_pkts} source packets, {bayseflow_object.source_payload_bytes} source "
                  f"bytes, {bayseflow_object.dest_pkts} dest packets, {bayseflow_object.dest_payload_bytes} dest bytes"
                  f" for protocol {bayseflow_object.protocol_information}")
            bayseflow_object.set_bayseflow_duration()


def netflow_2_bayseflows(utils, dnshelper):
    """Given a plaintext log file of unidirectional netflow records that has been lightly validated,
       store the netflows, collect both local and public DNS lookups, and convert the remaining netflows to BayseFlows.
    """

    # store file as a dict for easier processing
    store_netflows(utils)

    # collect DNS records (both local and public lookups)
    #dnshelper.collect_dns_records_from_netflow_sample()  # TODO: Is there anything we can do here?

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
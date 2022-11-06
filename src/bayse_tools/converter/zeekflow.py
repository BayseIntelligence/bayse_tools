"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains the ZeekFlow class, which captures the fields that are found in a Zeek flow from the conn.log
    file. Formatting should always look like the following ("field #" lines are my annotation) _UNLESS_ it is a JSON
    Zeek file:

        Field #  1       2        3                 4               5
                ts      uid     id.orig_h       id.orig_p       id.resp_h
        Field #    6             7        8        9               10
                id.resp_p       proto   service duration        orig_bytes
        Field #     11              12              13              14
                resp_bytes      conn_state      local_orig      local_resp
        Field #     15             16      17               18             19
                missed_bytes    history orig_pkts       orig_ip_bytes  resp_pkts
        Field #       20              21
                resp_ip_bytes   tunnel_parents

    An example of a flow line from the conn log is as follows ("field #" lines are my annotation):

        Field #       1                        2                      3
                1601060272.439360       CC9S3G178KjzSMTGRk      192.168.100.224
        Field #   4             5        6       7       8          9
                 137    192.168.100.255 137     udp     dns     12.114023
        Field #  10     11    12      13     14      15      16       17
                1186    0     S0      -       -       0       D       23
        Field #  18     19      20      21
                1830    0       0       -

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import copy

class ZeekFlow():
    def __init__(self, flowdata, is_json=False):
        if is_json:
            try:
                self.bayseflow_key = f'{flowdata["id.orig_h"]}:{flowdata["id.orig_p"]}-{flowdata["id.resp_h"]}:' \
                                     f'{flowdata["id.resp_p"]}'
                self.timestamp = float(flowdata["ts"])
                self.unique_id = f'{flowdata["uid"]}'
                self.source_ip = f'{flowdata["id.orig_h"]}'
                self.source_port = f'{flowdata["id.orig_p"]}'
                self.dest_ip = f'{flowdata["id.resp_h"]}'
                self.dest_port = f'{flowdata["id.resp_p"]}'
                self.trans_proto = f'{flowdata["proto"].lower()}' if "proto" in flowdata else "-"
                self.protocol_information = ""
                if self.trans_proto == "icmp":
                    self.source_port = ""
                    self.dest_port = ""
                    self.protocol_information = "ICMP"
                    self.bayseflow_key = f'{self.source_ip}:{self.protocol_information}-' \
                                         f'{self.dest_ip}:{self.protocol_information}'
                elif self.trans_proto == "udp":
                    self.protocol_information = "UDP"
                elif self.trans_proto == "tcp":
                    self.protocol_information = "TCP"
                self.service = f'{flowdata["service"]}' if "service" in flowdata else "-"
                self.duration = f'{flowdata["duration"]}' if "duration" in flowdata else "-"
                self.source_bytes = f'{flowdata["orig_bytes"]}' if "orig_bytes" in flowdata else "-"
                self.dest_bytes = f'{flowdata["resp_bytes"]}' if "resp_bytes" in flowdata else "-"
                self.connection_state = f'{flowdata["conn_state"]}' if "conn_state" in flowdata else "-"
                self.local_orig = f'{flowdata["local_orig"]}' if "local_orig" in flowdata else "-"
                self.local_resp = f'{flowdata["local_resp"]}' if "local_resp" in flowdata else "-"
                self.missed_bytes = f'{flowdata["missed_bytes"]}' if "missed_bytes" in flowdata else "0"
                self.history = f'{flowdata["history"]}' if "history" in flowdata else "-"
                self.source_pkts = f'{flowdata["orig_pkts"]}' if "orig_pkts" in flowdata else "0"
                self.source_ip_bytes = f'{flowdata["orig_ip_bytes"]}' if "orig_ip_bytes" in flowdata else "0"
                self.dest_pkts = f'{flowdata["resp_pkts"]}' if "resp_pkts" in flowdata else "0"
                self.dest_ip_bytes = f'{flowdata["resp_ip_bytes"]}' if "resp_ip_bytes" in flowdata else "0"
                self.tunnel_parents = f'{flowdata["tunnel_parents"]}' if "tunnel_parents" in flowdata else "-"
            except Exception as e:
                print("Something went wrong while trying to parse JSON record for Zeek:\n{}".format(e))
                self.bayseflow_key = None
        else:
            try:
                # TSV format matching the field as structured at top of this file
                self.bayseflow_key = f"{flowdata[2]}:{flowdata[3]}-{flowdata[4]}:{flowdata[5]}"  # useful for later
                # conversion, but also use it here.
                self.timestamp = float(flowdata[0])
                self.unique_id = f'{flowdata[1]}'
                self.source_ip = flowdata[2]
                self.source_port = flowdata[3]
                self.dest_ip = flowdata[4]
                self.dest_port = flowdata[5]
                self.trans_proto = flowdata[6].lower()
                self.protocol_information = ""
                if self.trans_proto == "icmp":
                    self.source_port = ""
                    self.dest_port = ""
                    self.protocol_information = "ICMP"
                    self.bayseflow_key = f"{self.source_ip}:{self.protocol_information}-" \
                                         f"{self.dest_ip}:{self.protocol_information}"
                elif self.trans_proto == "udp":
                    self.protocol_information = "UDP"
                elif self.trans_proto == "tcp":
                    self.protocol_information = "TCP"
                self.service = flowdata[7]
                self.duration = flowdata[8]
                self.source_bytes = flowdata[9]
                self.dest_bytes = flowdata[10]
                self.connection_state = flowdata[11]
                self.local_orig = flowdata[12]
                self.local_resp = flowdata[13]
                self.missed_bytes = flowdata[14]
                self.history = flowdata[15]
                self.source_pkts = flowdata[16]
                self.source_ip_bytes = flowdata[17]
                self.dest_pkts = flowdata[18]
                self.dest_ip_bytes = flowdata[19]
                self.tunnel_parents = flowdata[20]
            except Exception as e:
                print("Something went wrong while trying to parse plaintext record for Zeek:\n{}".format(e))
                self.bayseflow_key = None


    def flip_zeek_order(self):
        orig_zeek_flow = copy.deepcopy(self)
        if self.protocol_information != "ICMP":
            self.bayseflow_key = f"{orig_zeek_flow.dest_ip}:{orig_zeek_flow.dest_port}-" \
                                 f"{orig_zeek_flow.source_ip}:{orig_zeek_flow.source_port}"
        else:
            self.bayseflow_key = f"{orig_zeek_flow.dest_ip}:{self.protocol_information}-" \
                                 f"{orig_zeek_flow.source_ip}:{self.protocol_information}"
        self.source_ip = orig_zeek_flow.dest_ip
        self.source_port = orig_zeek_flow.dest_port
        self.dest_ip = orig_zeek_flow.source_ip
        self.dest_port = orig_zeek_flow.source_port
        self.source_bytes = orig_zeek_flow.dest_bytes
        self.dest_bytes = orig_zeek_flow.source_bytes
        self.history = orig_zeek_flow.history.swapcase()
        self.source_pkts = orig_zeek_flow.dest_pkts
        self.source_ip_bytes = orig_zeek_flow.dest_ip_bytes
        self.dest_pkts = orig_zeek_flow.source_pkts
        self.dest_ip_bytes = orig_zeek_flow.source_ip_bytes
"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains the Interflow class, which captures the fields that are found in Stellar Cyber's Interflow format
    for network traffic. Note that there are MANY fields in Interflow that will not be a part of this converter, as they
    are not necessary to convert to BayseFlow. The file is expected to contain one Interflow per line in JSON format,
    and any DNS Interflow records (if provided) are expected to also be contained within the file. For non-DNS records,
    below is an example Interflow record that includes only the fields we need (split into multiple lines for
    readability purposes only).

    {"timestamp": 1656517273641, "duration": 401, "_id": "6c0liABC8qtQm3loQr7H", "msg_class": "interflow_traffic",
     "srcip": "172.18.40.120", "srcport": 55503,"dstip": "142.251.40.65", "dstip_host": "ci3.googleusercontent.com",
     "dstport": 80, "proto_name": "tcp", "outbytes_total": 0, "inpkts_delta": 5, "outpkts_delta": 0,
     "inbytes_total": 17765
    }

    Note that if we are missing some of the outbytes, outpkts, inbytes, or inpkts fields, we will attempt to compensate
    whenever possible. Any Interflow records that have nonsensical (i.e. totalpackets = 0) or no packet and byte data
    will be ignored.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

from bayse_tools.converter import interflowutils
import math

class Interflow():
    def __init__(self, flowdata, is_json=False):
        likely_ms = True  # the time information is likely in milliseconds, so fix up duration and timestamp
        if is_json:
            try:
                max_segment_size = 1514  # used for guesstimation in worst-case scenarios with fields
                missing = []  # collect fields we're missing
                # absolutely mandatory fields
                srcip_vals = interflowutils.json_extract(flowdata, "srcip")
                srcport_vals = interflowutils.json_extract(flowdata, "srcport")
                dstip_vals = interflowutils.json_extract(flowdata, "dstip")
                dstport_vals = interflowutils.json_extract(flowdata, "dstport")
                ts_vals = interflowutils.json_extract(flowdata, "timestamp")

                # fields that we can possibly interpret if only some are missing
                duration_vals = interflowutils.json_extract(flowdata, "duration")
                outbytes_vals = interflowutils.json_extract(flowdata, "outbytes_total")
                inbytes_vals = interflowutils.json_extract(flowdata, "inbytes_total")
                totalbytes_vals = interflowutils.json_extract(flowdata, "totalbytes")
                outpkts_vals = interflowutils.json_extract(flowdata, "outpkts_delta")
                total_outpkts_vals = interflowutils.json_extract(flowdata, "outpkts_total")
                inpkts_vals = interflowutils.json_extract(flowdata, "inpkts_delta")
                total_inpkts_vals = interflowutils.json_extract(flowdata, "inpkts_total")
                totalpkts_vals = interflowutils.json_extract(flowdata, "totalpackets")

                """
                print(f"All relevant values found for Interflow {srcip_vals[0]}:{srcport_vals[0]} <-> {dstip_vals[0]}:{dstport_vals[0]}:\n"
                      f"totalpackets: {totalpkts_vals} total_outpkts: {total_outpkts_vals} total_inpkts: {total_inpkts_vals}"
                      f"outpkts: {outpkts_vals} inpkts: {inpkts_vals}\n"
                      f"totalbytes: {totalbytes_vals} outbytes: {outbytes_vals} inbytes: {inbytes_vals}")
                """
                if not srcip_vals:
                    missing += ["srcip"]
                if not srcport_vals:
                    missing += ["srcport"]
                if not dstip_vals:
                    missing += ["dstip"]
                if not dstport_vals:
                    missing += ["dstport"]
                if not ts_vals:
                    missing += ["timestamp"]

                if len(missing) > 0:  # short-circuit here first if failed with absolutely mandatory fields
                    print(f"Mandatory fields missing from JSON record for Interflow: {missing}")
                    self.bayseflow_key = None
                    return

                # interpretable things
                if not duration_vals:
                    #missing += ["duration"]
                    print("Missing duration...could cause problems with functionality!")
                    # NOTE: This is not 100% critical, but we should try to figure something out...
                if not outbytes_vals:
                    if not totalbytes_vals or not inbytes_vals:  # we need 2 of 3  to calculate the other
                        missing += ["outbytes_total"]
                    else:
                        outbytes_vals = [totalbytes_vals[0] - inbytes_vals[0]]
                        print(f"Calculated outbytes {outbytes_vals} from totalbytes-inbytes")
                if not inbytes_vals:
                    if not totalbytes_vals or not outbytes_vals:  # same as above
                        missing += ["inbytes_total"]
                    else:
                        inbytes_vals = [totalbytes_vals[0] - outbytes_vals[0]]
                        print(f"Calculated inbytes {inbytes_vals} from totalbytes-outbytes")
                if not outpkts_vals and not total_outpkts_vals:
                    if not totalpkts_vals or totalpkts_vals[0] == 0:  # 0 total packets makes no sense...
                        if not outbytes_vals:  # if we don't have this we can't even take a guesstimate
                            print(f"Failed to find valid totalpackets value and outbytes value (which we could've "
                                  f"used to guess on number of packets)"
                                  )
                            missing += ["outpkts_delta"]
                        else:
                            # roughly guess on number of outgoing packets
                            outpkts_vals = [math.ceil(outbytes_vals[0]/max_segment_size)]
                    else:  # we have a totalpackets count that seemingly makes sense, so try to use it
                        if not inpkts_vals:
                            if not inbytes_vals:
                                print("Failed to find valid inpkts and outpkts values")
                                missing += ["outpkts_delta"]
                            else:  # we have inbytes and totalpackets, so we can create a guesstimate here
                                print(f"Failed to find valid inpkts value, so using totalpackets - (inbytes/MSS) to "
                                      f"guess on outpkts"
                                      )
                                outpkts_vals = [totalpkts_vals[0] - int(math.ceil(inbytes_vals[0]/max_segment_size))]
                        else:
                            # we have totalpackets and inpkts, so we should be able to infer outpkts
                            outpkts_vals = [totalpkts_vals[0] - inpkts_vals[0]]
                            print(f"Calculated outpkts {outpkts_vals} from totalpackets-inpkts")
                if len(total_outpkts_vals) > 0 and not outpkts_vals:
                    print(f"No value for outpkts_delta, so using outpkts_total in its place.")
                    outpkts_vals = [total_outpkts_vals[0]]
                if not inpkts_vals and not total_inpkts_vals:
                    if not totalpkts_vals or totalpkts_vals[0] == 0:  # 0 total packets makes no sense...
                        if not inbytes_vals:  # if we don't have this we can't even take a guesstimate
                            print(f"Failed to find valid totalpackets value and inbytes value (which we could've used "
                                  f"to guess on number of packets)"
                                  )
                            missing += ["inpkts_delta"]
                        else:
                            # roughly guess on number of incoming packets
                            inpkts_vals = [math.ceil(inbytes_vals[0]/max_segment_size)]
                    else:  # we have a totalpackets count that seemingly makes sense, so try to use it
                        if not outpkts_vals:
                            if not outbytes_vals:
                                print("Failed to find valid outpkts and inpkts values")
                                missing += ["inpkts_delta"]
                            else:  # we have outbytes and totalpackets, so we can create a guesstimate here
                                print(f"Failed to find valid outpkts value, so using totalpackets - (outbytes/MSS) to "
                                      f"guess on inpkts"
                                      )
                                inpkts_vals = [totalpkts_vals[0] - int(math.ceil(outbytes_vals[0]/max_segment_size))]
                        else:
                            # we have totalpackets and outpkts, so we should be able to infer inpkts
                            inpkts_vals = [totalpkts_vals[0] - outpkts_vals[0]]
                            print(f"Calculated inpkts {inpkts_vals} from totalpackets-outpkts")
                if len(total_inpkts_vals) > 0 and not inpkts_vals:
                    print(f"No value for inpkts_delta, so using inpkts_total in its place.")
                    inpkts_vals = [total_inpkts_vals[0]]

                if len(missing) > 0:
                    print(f"Mandatory fields missing from JSON record for Interflow: {missing}")
                    self.bayseflow_key = None
                    return
                # non-mandatory but desired fields
                dstip_host_vals = interflowutils.json_extract(flowdata, "dstip_host")
                proto_vals = interflowutils.json_extract(flowdata, "proto_name")
                service_vals = interflowutils.json_extract(flowdata, "service")

                self.bayseflow_key = f'{srcip_vals[0]}:{srcport_vals[0]}-{dstip_vals[0]}:{dstport_vals[0]}'
                ts = ts_vals[0]
                if len(str(ts)) == 13:
                    if "." not in str(ts):
                        self.timestamp = float(ts) / 1000.0
                    else:
                        print("Unrecognized timestamp format. Results may be wrong.")
                        likely_ms = False
                        self.timestamp = float(ts)
                elif len(str(ts)) == 10:
                    likely_ms = False
                    self.timestamp = float(ts)
                self.unique_id = f'{flowdata["_id"]}'
                self.source_ip = f'{srcip_vals[0]}'
                self.source_port = f'{srcport_vals[0]}'
                self.dest_ip = f'{dstip_vals[0]}'
                self.dest_port = f'{dstport_vals[0]}'
                self.proposed_destname = f'{dstip_host_vals[0]}' if len(dstip_host_vals) > 0 else None
                self.trans_proto = f'{proto_vals[0].lower()}' if len(proto_vals) > 0 else "-"
                self.protocol_information = ""
                #TODO: Is ICMPv6 considered icmp?
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
                self.service = f'{service_vals[0]}' if len(service_vals) > 0 else "-"
                if "duration" in flowdata:
                    if likely_ms:
                        self.duration = f'{float(duration_vals[0]) / 1000.0}'
                    else:
                        self.duration = f'{duration_vals[0]}'
                else:
                    self.duration = "-"
                self.source_bytes = f'{outbytes_vals[0]}' if len(outbytes_vals) > 0 else "-"
                self.dest_bytes = f'{inbytes_vals[0]}' if len(inbytes_vals) > 0 else "-"
                self.source_pkts = f'{outpkts_vals[0]}' if len(outpkts_vals) > 0 else "0"
                self.dest_pkts = f'{inpkts_vals[0]}' if len(inpkts_vals) > 0 else "0"
            except Exception as e:
                print("Something went wrong while trying to parse JSON record for Interflow:\n{}".format(e))
                self.bayseflow_key = None
        else:
            print(f"Interflow data not recognized. We only accept Interflow records in JSON format, with each record "
                  f"in a comma-separated list."
                  )
            self.bayseflow_key = None